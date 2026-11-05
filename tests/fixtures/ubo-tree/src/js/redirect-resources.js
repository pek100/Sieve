// Sieve-authored, in the shape of uBlock Origin's redirect map: no uBO code.
export default new Map([
  ["sieve-noop.js", { alias: "sieve-noopjs", data: "text" }],
  ["sieve-pixel.gif", { alias: ["sieve-1x1.gif"], data: "blob" }],
  ["sieve-parameterised.js", { data: "text", params: ["delay"] }],
]);
