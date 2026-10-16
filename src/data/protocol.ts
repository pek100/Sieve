/**
 * Snapshot protocol v1 (primitive B1). Mirrored in src-tauri/src/protocol.rs.
 * Raw facts about the machine only, no judgement: which processes exist and
 * which sockets they own. Changing the shape bumps PROTOCOL_VERSION and the
 * fixture (src/data/fixtures/snapshot-v1.json) in the same commit.
 */

export const PROTOCOL_VERSION = 1 as const;

export const PROTOS = ["tcp", "udp"] as const;
export type Proto = (typeof PROTOS)[number];

export const FAMILIES = ["v4", "v6"] as const;
export type Family = (typeof FAMILIES)[number];

/** TCP states in MIB_TCP_STATE order (code 1 to 12), then `none` for UDP. */
export const FLOW_STATES = [
  "closed",
  "listen",
  "syn_sent",
  "syn_received",
  "established",
  "fin_wait_1",
  "fin_wait_2",
  "close_wait",
  "closing",
  "last_ack",
  "time_wait",
  "delete_tcb",
  "none",
] as const;
export type FlowState = (typeof FLOW_STATES)[number];

export interface Endpoint {
  addr: string;
  port: number;
}

export interface ProcessInfo {
  pid: number;
  /** Full image path, or null when the OS refused to tell us. */
  exe: string | null;
  /** Display name: exe file name, or "System" / "pid <n>" when exe is null. */
  name: string;
  /** ProductName from the exe's version info, when present. */
  product: string | null;
}

export interface Flow {
  pid: number;
  proto: Proto;
  family: Family;
  local: Endpoint;
  /** null for listening TCP sockets and for every UDP socket. */
  remote: Endpoint | null;
  state: FlowState;
}

export interface Snapshot {
  v: typeof PROTOCOL_VERSION;
  /** Sample time, ms since the Unix epoch, from the sampling side's clock. */
  t: number;
  processes: ProcessInfo[];
  flows: Flow[];
}

export class ProtocolError extends Error {
  constructor(message: string) {
    super(`Snapshot protocol: ${message}`);
    this.name = "ProtocolError";
  }
}

type Rec = Record<string, unknown>;

function isRec(x: unknown): x is Rec {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function int(x: unknown, where: string): number {
  if (typeof x !== "number" || !Number.isInteger(x) || x < 0) {
    throw new ProtocolError(`${where} must be a non-negative integer`);
  }
  return x;
}

function str(x: unknown, where: string): string {
  if (typeof x !== "string") throw new ProtocolError(`${where} must be a string`);
  return x;
}

function strOrNull(x: unknown, where: string): string | null {
  return x === null ? null : str(x, where);
}

function oneOf<T extends string>(x: unknown, options: readonly T[], where: string): T {
  if (typeof x !== "string" || !(options as readonly string[]).includes(x)) {
    throw new ProtocolError(`${where} must be one of ${options.join(", ")}`);
  }
  return x as T;
}

function endpoint(x: unknown, where: string): Endpoint {
  if (!isRec(x)) throw new ProtocolError(`${where} must be an object`);
  const port = int(x.port, `${where}.port`);
  if (port > 65535) throw new ProtocolError(`${where}.port out of range`);
  return { addr: str(x.addr, `${where}.addr`), port };
}

/** Validate an untrusted value as a v1 Snapshot. Throws ProtocolError. */
export function parseSnapshot(x: unknown): Snapshot {
  if (!isRec(x)) throw new ProtocolError("snapshot must be an object");
  if (x.v !== PROTOCOL_VERSION) {
    throw new ProtocolError(`version ${String(x.v)} is not ${PROTOCOL_VERSION}`);
  }
  const t = int(x.t, "t");
  if (!Array.isArray(x.processes)) throw new ProtocolError("processes must be an array");
  if (!Array.isArray(x.flows)) throw new ProtocolError("flows must be an array");

  const processes = x.processes.map((p, i): ProcessInfo => {
    const w = `processes[${i}]`;
    if (!isRec(p)) throw new ProtocolError(`${w} must be an object`);
    return {
      pid: int(p.pid, `${w}.pid`),
      exe: strOrNull(p.exe, `${w}.exe`),
      name: str(p.name, `${w}.name`),
      product: strOrNull(p.product, `${w}.product`),
    };
  });

  const flows = x.flows.map((f, i): Flow => {
    const w = `flows[${i}]`;
    if (!isRec(f)) throw new ProtocolError(`${w} must be an object`);
    return {
      pid: int(f.pid, `${w}.pid`),
      proto: oneOf(f.proto, PROTOS, `${w}.proto`),
      family: oneOf(f.family, FAMILIES, `${w}.family`),
      local: endpoint(f.local, `${w}.local`),
      remote: f.remote === null ? null : endpoint(f.remote, `${w}.remote`),
      state: oneOf(f.state, FLOW_STATES, `${w}.state`),
    };
  });

  return { v: PROTOCOL_VERSION, t, processes, flows };
}
