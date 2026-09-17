// Shared flag parsing for the CLI commands.
import { DEFAULT_PATH, param } from "./mldsa.js";

export function parseCommon(argv, extra = {}) {
  const out = {
    path: DEFAULT_PATH,
    level: 44,
    transport: "hid",
    outFile: null,
    ...extra,
  };
  const positional = [];
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    if (!k.startsWith("--")) {
      positional.push(k);
      continue;
    }
    const v = argv[i + 1];
    switch (k) {
      case "--path": out.path = v; i++; break;
      case "--mldsa": out.level = Number(v); i++; break;
      case "--speculos": {
        // optional host:port argument
        if (v && !v.startsWith("--")) { out.transport = `speculos:${v}`; i++; }
        else out.transport = "speculos";
        break;
      }
      case "--out": out.outFile = v; i++; break;
      default: {
        // --chain-id and --entry-point address the chainId / entryPoint keys.
        const name = k.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
        if (!(name in out)) throw new Error(`unknown flag: ${k}`);
        // A flag whose default is a boolean is a switch: it takes no value.
        if (typeof out[name] === "boolean") {
          out[name] = true;
          break;
        }
        out[name] = v;
        i++;
      }
    }
  }
  out.param = param(out.level);
  out.positional = positional;
  return out;
}

export const hex = (b) => Buffer.from(b).toString("hex");

export function hexToBytes(h) {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  if (s.length % 2) throw new Error("odd-length hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}
