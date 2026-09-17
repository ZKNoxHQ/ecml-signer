// Ledger transport wrapper for the ECML-Signer ML-DSA and hybrid INS.
//
// Wire protocol: see lib/mldsa.js (the parameter set rides in P2: 0x00 =
// ML-DSA-44, 0x01 = ML-DSA-65).
//
// Two transports are available:
//   * a physical device over HID (the default);
//   * a Speculos emulator over its APDU TCP port (--speculos [host:port]),
//     which is how the flows are exercised without hardware.

// Use the CJS build directly: the package's ESM build (lib-es/) omits `.js`
// extensions on relative imports, which Node's strict ESM resolver rejects.
import TransportNodeHid from "@ledgerhq/hw-transport-node-hid/lib/TransportNodeHid";
import net from "node:net";

export {
  DEFAULT_PATH,
  PARAMS,
  param,
  packDerivationPath,
  keygen,
  signTxMldsa,
  hybridSignHash,
  hybridSignUserOp,
  getPublicKeyChunks,
  getSignatureChunks,
} from "./mldsa.js";

import { signTxMldsa, param } from "./mldsa.js";

/**
 * Minimal Speculos APDU transport: length-prefixed APDUs on a TCP socket,
 * same `send(cla, ins, p1, p2, data)` shape as @ledgerhq/hw-transport.
 * Throws on a non-0x9000 status word, like the HID transport does.
 */
class SpeculosTransport {
  constructor(socket) {
    this.socket = socket;
    this.queue = [];
    this.buf = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      while (this.buf.length >= 4) {
        const len = this.buf.readUInt32BE(0);
        if (this.buf.length < 4 + len) break;
        const body = this.buf.subarray(4, 4 + len);
        this.buf = this.buf.subarray(4 + len);
        const pending = this.queue.shift();
        if (pending) pending.resolve(body);
      }
    });
    socket.on("error", (e) => {
      const pending = this.queue.shift();
      if (pending) pending.reject(e);
    });
  }

  static async open(hostPort = "127.0.0.1:5001") {
    const [host, port] = hostPort.split(":");
    const socket = await new Promise((resolve, reject) => {
      const s = net.createConnection({ host, port: Number(port) }, () => resolve(s));
      s.on("error", reject);
    });
    return new SpeculosTransport(socket);
  }

  async send(cla, ins, p1, p2, data = Buffer.alloc(0)) {
    const apdu = Buffer.concat([Buffer.from([cla, ins, p1, p2, data.length]), Buffer.from(data)]);
    const framed = Buffer.concat([(() => {
      const l = Buffer.alloc(4);
      l.writeUInt32BE(apdu.length, 0);
      return l;
    })(), apdu]);
    const response = await new Promise((resolve, reject) => {
      this.queue.push({ resolve, reject });
      this.socket.write(framed);
    });
    // Speculos returns [data || SW]; the HID transport's contract is the same.
    const sw = response.readUInt16BE(response.length - 2);
    if (sw !== 0x9000) {
      const err = new Error(`APDU failed: ${sw.toString(16)}`);
      err.statusCode = sw;
      throw err;
    }
    return response;
  }

  async close() {
    this.socket.destroy();
  }
}

/**
 * Open a transport. `target` is "hid" (default) or "speculos[:host:port]".
 */
export async function openTransport(target = "hid") {
  if (target === "hid") return TransportNodeHid.default.create();
  if (target.startsWith("speculos")) {
    const hostPort = target.includes(":") ? target.slice(target.indexOf(":") + 1) : "127.0.0.1:5001";
    return SpeculosTransport.open(hostPort);
  }
  throw new Error(`unknown transport: ${target}`);
}

/**
 * Backwards-compatible helper: SIGN_TX_MLDSA with ML-DSA-44 unless told
 * otherwise, returning {pk, sig}.
 */
export async function signMldsa(transport, path, txBytes, level = 44) {
  return signTxMldsa(transport, path, txBytes, param(level));
}
