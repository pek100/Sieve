// Sieve-authored, in the shape of current uBlock Origin: dependencies declared as a class
// and as an async function, which a bundle prepends and never calls. No uBO code.
class SieveListParser {
  split(text) {
    return text.split(",");
  }
}

async function sieveLaterFn(value) {
  return value;
}

function sieveSetList(text = "") {
  sieveLaterFn(new SieveListParser().split(text)).then((parts) => {
    globalThis.sieveFixtureList = parts;
  });
}

// Named trusted with no requiresTrust, as uBO 3762a26 registers trusted-prevent-xhr.js.
function trustedSieveUnflagged() {
  globalThis.sieveFixtureUnflagged = true;
}

export const builtinScriptlets = [
  { name: "sieve-list-parser.fn", fn: SieveListParser },
  { name: "sieve-later.fn", fn: sieveLaterFn },
  { name: "sieve-set-list.js", fn: sieveSetList, dependencies: ["sieve-list-parser.fn", "sieve-later.fn"] },
  { name: "trusted-sieve-unflagged.js", fn: trustedSieveUnflagged },
];
