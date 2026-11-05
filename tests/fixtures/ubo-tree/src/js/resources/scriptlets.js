// Sieve-authored scriptlets in the shape of uBlock Origin's module: no uBO code.
function sieveFlagName(name) {
  return `sieveFixture_${name}`;
}

function sieveSetFlag(name = "", value = "") {
  globalThis[sieveFlagName(name)] = value;
}

function sieveTrustedFlag(name = "") {
  globalThis[sieveFlagName(name)] = "trusted";
}

export const builtinScriptlets = [
  { name: "sieve-flag-name.fn", fn: sieveFlagName },
  {
    name: "sieve-set-flag.js",
    aliases: ["ssf.js"],
    fn: sieveSetFlag,
    dependencies: ["sieve-flag-name.fn"],
  },
  {
    name: "trusted-sieve-flag.js",
    fn: sieveTrustedFlag,
    dependencies: [sieveFlagName],
    requiresTrust: true,
    world: "ISOLATED",
  },
];
