// The part of the global WebAssembly the host libraries use, backed by WAMR's classic interpreter
// through build/wamr.node. Swapping it in runs their own tests, unchanged, on the interpreter the device uses
import { createRequire } from "node:module";

const wamr = createRequire(import.meta.url)("../build/wamr.node");

class Module {
  constructor(bytes) {
    this.handle = wamr.loadModule(Buffer.from(bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes));
  }
  static imports(module) {
    return Array.from({ length: wamr.importCount(module.handle) }, () => ({ module: "?", name: "?", kind: "?" }));
  }
}

class Instance {
  constructor(module) {
    const instance = wamr.instantiate(module.handle);
    this.exports = {};
    for (const { name, kind } of wamr.exports(module.handle)) {
      if (kind === "function") this.exports[name] = (...args) => wamr.call(instance, name, args);
      else if (kind === "memory") this.exports[name] = { buffer: wamr.memory(instance) };
    }
  }
}

export default {
  Module,
  Instance,
  RuntimeError: Error,
  compile: async (bytes) => new Module(bytes),
  instantiate: async (source) => {
    if (source instanceof Module) return new Instance(source);
    const module = new Module(source);
    return { module, instance: new Instance(module) };
  },
};
