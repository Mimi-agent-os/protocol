// Session state machines: Noise IK handshake, mandatory ML-KEM-768 rekey, then stream records.
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { CipherState, Handshake } from "./noise.ts";
import { frame, FrameDecoder } from "./frame.ts";
import { RecordLayer } from "./records.ts";
import { FLAG_END, encodeStreamFrame, decodeStreamFrame, type ChannelStreamFrame } from "./stream.ts";

export interface ServerInfo {
  protocol: number;
  activation?: "pending";
}

export type ClientEvent =
  | { type: "ready"; info: ServerInfo }
  | { type: "frame"; frame: ChannelStreamFrame }
  | { type: "error"; code: string; peer?: number | undefined }
  | { type: "close" };

export type ServerEvent =
  | { type: "hello"; clientPub: Uint8Array }
  | { type: "ready" }
  | { type: "frame"; frame: ChannelStreamFrame }
  | { type: "close" };

type ClientStage = "idle" | "msg2" | "kem" | "info" | "ready" | "closed";

type ServerStage = "msg1" | "kem" | "gate" | "ready" | "closed";

const utf8 = new TextEncoder();
const utf8d = new TextDecoder();
const PROLOGUE = utf8.encode("mimi/session/v1");
const KEM_PUB_LEN = 1184;
const KEM_CT_LEN = 1088;
const TAG_LEN = 16;
const IK_MSG1_LEN = 96;
const IK_MSG2_LEN = 48;
const CONTROL_RECORD_MAX = 1024;

// Each control message is a whole stream-0 message, so it ends on its only frame.
function controlRecord(records: RecordLayer, msg: Record<string, unknown>): Uint8Array {
  return records.seal(encodeStreamFrame({ stream: 0, flags: FLAG_END, payload: utf8.encode(JSON.stringify(msg)) }));
}

// A record that fails to decrypt still throws; anything but a stream-0 JSON message reads as null.
function openControl(records: RecordLayer, ct: Uint8Array): { t?: unknown; code?: unknown; protocol?: unknown; activation?: unknown } | null {
  const pt = records.open(ct);
  try {
    const f = decodeStreamFrame(pt);
    if (f.stream !== 0 || f.flags !== FLAG_END) return null;
    const msg: unknown = JSON.parse(utf8d.decode(f.payload));
    return msg !== null && typeof msg === "object" && !Array.isArray(msg) ? msg : null;
  } catch {
    return null;
  }
}

// Both directions rekey from (old transport key || kem shared secret), salted by the handshake hash.
function pqRekey(records: RecordLayer, initiator: boolean, oldSend: CipherState, oldRecv: CipherState, shared: Uint8Array, hh: Uint8Array): void {
  const sensitive = [shared];
  try {
    const c2gOld = initiator ? oldSend.key : oldRecv.key;
    sensitive.push(c2gOld);
    const g2cOld = initiator ? oldRecv.key : oldSend.key;
    sensitive.push(g2cOld);
    const c2gIkm = concatBytes(c2gOld, shared);
    sensitive.push(c2gIkm);
    const g2cIkm = concatBytes(g2cOld, shared);
    sensitive.push(g2cIkm);
    const c2g = hkdf(sha256, c2gIkm, hh, utf8.encode("mimi/pq1/c2g"), 32);
    sensitive.push(c2g);
    const g2c = hkdf(sha256, g2cIkm, hh, utf8.encode("mimi/pq1/g2c"), 32);
    sensitive.push(g2c);
    records.install(new CipherState(initiator ? c2g : g2c), new CipherState(initiator ? g2c : c2g));
  } finally {
    for (const bytes of sensitive) bytes.fill(0);
  }
}

export class ClientSession {
  #hs: Handshake | null;
  #protocol: number;
  #stage: ClientStage = "idle";
  #frames = new FrameDecoder(IK_MSG2_LEN, IK_MSG2_LEN);
  #records: RecordLayer | null = null;
  #send: CipherState | null = null;
  #recv: CipherState | null = null;
  #kem: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
  #hh: Uint8Array | null = null;

  public constructor(o: { s: Uint8Array; gatewayPub: Uint8Array; protocol: number }) {
    this.#hs = new Handshake({ pattern: "IK", initiator: true, prologue: PROLOGUE, s: o.s, rs: o.gatewayPub });
    this.#protocol = o.protocol;
  }

  public start(): Uint8Array[] {
    if (this.#stage !== "idle") throw new Error("already started");
    this.#stage = "msg2";
    try {
      return [frame(this.#hs!.writeMessage())];
    } catch (error) {
      this.#destroy();
      throw error;
    }
  }

  public feed(bytes: Uint8Array): { out: Uint8Array[]; events: ClientEvent[] } {
    if (this.#stage === "closed") return { out: [], events: [] };
    if (this.#stage === "idle") throw new Error("session not started");
    const out: Uint8Array[] = [];
    const events: ClientEvent[] = [];
    try {
      for (const chunk of this.#frames.feed(bytes)) {
        this.#handle(chunk, out, events);
        if (this.#isClosed()) break;
      }
    } catch (error) {
      this.#destroy();
      throw error;
    }
    return { out, events };
  }

  public send(frame: ChannelStreamFrame): Uint8Array[] {
    if (this.#stage !== "ready") throw new Error("session not ready");
    return [this.#records!.seal(encodeStreamFrame(frame))];
  }

  public destroy(): void {
    this.#destroy();
  }

  #handle(chunk: Uint8Array, out: Uint8Array[], events: ClientEvent[]): void {
    switch (this.#stage) {
      case "msg2": {
        const hs = this.#hs!;
        hs.readMessage(chunk);
        const { send, recv } = hs.split();
        this.#send = send;
        this.#recv = recv;
        this.#records = new RecordLayer(send, recv);
        this.#hh = hs.handshakeHash;
        this.#hs = null;
        this.#kem = ml_kem768.keygen();
        this.#frames.setBounds(KEM_CT_LEN + TAG_LEN, KEM_CT_LEN + TAG_LEN);
        out.push(this.#records.seal(this.#kem.publicKey)); // kem pub doubles as the liveness proof
        this.#stage = "kem";
        break;
      }
      case "kem": {
        const ct = this.#records!.open(chunk);
        if (ct.length !== KEM_CT_LEN) throw new Error("bad kem ciphertext record");
        const shared = ml_kem768.decapsulate(ct, this.#kem!.secretKey);
        pqRekey(this.#records!, true, this.#send!, this.#recv!, shared, this.#hh!);
        this.#kem!.secretKey.fill(0);
        this.#kem = null;
        this.#send = null;
        this.#recv = null;
        this.#hh!.fill(0);
        this.#hh = null;
        this.#frames.setBounds(TAG_LEN, CONTROL_RECORD_MAX);
        this.#stage = "info";
        break;
      }
      case "info": {
        const msg = openControl(this.#records!, chunk);
        if (msg?.t === "server_info" && msg.protocol === this.#protocol && (msg.activation === undefined || msg.activation === "pending")) {
          events.push({ type: "ready", info: msg.activation === "pending" ? { protocol: this.#protocol, activation: "pending" } : { protocol: this.#protocol } });
          out.push(controlRecord(this.#records!, { t: "client_ready", protocol: this.#protocol }));
          this.#frames.setBounds(TAG_LEN, 0xffff);
          this.#stage = "ready";
          break;
        }
        if (msg?.t === "error") events.push({ type: "error", code: typeof msg.code === "string" ? msg.code : "unknown" });
        if (msg?.t === "server_info" && typeof msg.protocol === "number" && msg.protocol !== this.#protocol) {
          out.push(controlRecord(this.#records!, { t: "error", code: "incompatible_protocol" }));
          events.push({ type: "error", code: "incompatible_protocol", peer: msg.protocol });
        }
        this.#destroy();
        events.push({ type: "close" });
        break;
      }
      case "ready":
        events.push({ type: "frame", frame: decodeStreamFrame(this.#records!.open(chunk)) });
    }
  }

  #destroy(): void {
    this.#stage = "closed";
    this.#frames.clear();
    this.#hs?.destroy();
    this.#hs = null;
    this.#kem?.secretKey.fill(0);
    this.#kem = null;
    this.#records?.destroy();
    this.#records = null;
    this.#send?.destroy();
    this.#recv?.destroy();
    this.#send = null;
    this.#recv = null;
    this.#hh?.fill(0);
    this.#hh = null;
  }

  #isClosed(): boolean {
    return this.#stage === "closed";
  }
}

export class ServerSession {
  #hs: Handshake | null;
  #protocol: number;
  #lookup: (clientPub: Uint8Array) => "active" | "pending" | "reject";
  #stage: ServerStage = "msg1";
  #frames = new FrameDecoder(IK_MSG1_LEN, IK_MSG1_LEN);
  #records: RecordLayer | null = null;
  #send: CipherState | null = null;
  #recv: CipherState | null = null;
  #hh: Uint8Array | null = null;
  #clientPub: Uint8Array | null = null;
  #pending = false;

  public constructor(o: { s: Uint8Array; protocol: number; lookup(clientPub: Uint8Array): "active" | "pending" | "reject" }) {
    this.#hs = new Handshake({ pattern: "IK", initiator: false, prologue: PROLOGUE, s: o.s });
    this.#protocol = o.protocol;
    this.#lookup = o.lookup;
  }

  public feed(bytes: Uint8Array): { out: Uint8Array[]; events: ServerEvent[] } {
    if (this.#stage === "closed") return { out: [], events: [] };
    const out: Uint8Array[] = [];
    const events: ServerEvent[] = [];
    try {
      for (const chunk of this.#frames.feed(bytes)) {
        this.#handle(chunk, out, events);
        if (this.#isClosed()) break;
      }
    } catch (error) {
      this.#destroy();
      throw error;
    }
    return { out, events };
  }

  public send(frame: ChannelStreamFrame): Uint8Array[] {
    if (this.#stage !== "ready") throw new Error("session not ready");
    if (this.#pending && frame.stream !== 0) throw new Error("pending session is stream-0 only");
    return [this.#records!.seal(encodeStreamFrame(frame))];
  }

  public activate(): Uint8Array[] {
    if (this.#stage !== "ready" || !this.#pending) throw new Error("nothing to activate");
    const record = controlRecord(this.#records!, { t: "activated" });
    this.#pending = false;
    return [record];
  }

  public destroy(): void {
    this.#destroy();
  }

  #handle(chunk: Uint8Array, out: Uint8Array[], events: ServerEvent[]): void {
    switch (this.#stage) {
      case "msg1": {
        const hs = this.#hs!;
        hs.readMessage(chunk);
        const clientPub = hs.remoteStatic!;
        this.#clientPub = clientPub;
        events.push({ type: "hello", clientPub: clientPub.slice() });
        out.push(frame(hs.writeMessage()));
        const { send, recv } = hs.split();
        this.#send = send;
        this.#recv = recv;
        this.#records = new RecordLayer(send, recv);
        this.#hh = hs.handshakeHash;
        this.#hs = null;
        this.#frames.setBounds(KEM_PUB_LEN + TAG_LEN, KEM_PUB_LEN + TAG_LEN);
        this.#stage = "kem";
        break;
      }
      case "kem": {
        const pt = this.#records!.open(chunk);
        // Uniform close point: unknown, revoked and denied clients all die here, after msg2 + kem pub.
        const lookedUp: unknown = pt.length === KEM_PUB_LEN ? this.#lookup(this.#clientPub!) : "reject";
        this.#clientPub = null;
        // This callback is an authorization boundary. Runtime adapters can violate
        // their TypeScript declaration, so only explicit allowlisted values pass.
        if (lookedUp !== "active" && lookedUp !== "pending") {
          if (lookedUp !== null && (typeof lookedUp === "object" || typeof lookedUp === "function")) {
            void Promise.resolve(lookedUp).catch(() => undefined);
          }
          this.#close(events);
          break;
        }
        const status = lookedUp;
        const { cipherText, sharedSecret } = ml_kem768.encapsulate(pt);
        try {
          out.push(this.#records!.seal(cipherText));
          pqRekey(this.#records!, false, this.#send!, this.#recv!, sharedSecret, this.#hh!);
        } finally {
          sharedSecret.fill(0);
        }
        this.#send = null;
        this.#recv = null;
        this.#hh!.fill(0);
        this.#hh = null;
        this.#pending = status === "pending";
        out.push(controlRecord(this.#records!, this.#pending ? { t: "server_info", protocol: this.#protocol, activation: "pending" } : { t: "server_info", protocol: this.#protocol }));
        this.#frames.setBounds(TAG_LEN, CONTROL_RECORD_MAX);
        this.#stage = "gate";
        break;
      }
      case "gate": {
        const msg = openControl(this.#records!, chunk);
        if (msg?.t === "client_ready" && msg.protocol === this.#protocol) {
          events.push({ type: "ready" });
          this.#frames.setBounds(TAG_LEN, 0xffff);
          this.#stage = "ready";
          break;
        }
        if (msg?.t === "client_ready" && typeof msg.protocol === "number") out.push(controlRecord(this.#records!, { t: "error", code: "incompatible_protocol" }));
        this.#close(events);
        break;
      }
      case "ready": {
        const f = decodeStreamFrame(this.#records!.open(chunk));
        if (this.#pending && f.stream !== 0) this.#close(events);
        else events.push({ type: "frame", frame: f });
      }
    }
  }

  #close(events: ServerEvent[]): void {
    this.#destroy();
    events.push({ type: "close" });
  }

  #destroy(): void {
    this.#stage = "closed";
    this.#frames.clear();
    this.#hs?.destroy();
    this.#hs = null;
    this.#records?.destroy();
    this.#records = null;
    this.#send?.destroy();
    this.#recv?.destroy();
    this.#send = null;
    this.#recv = null;
    this.#hh?.fill(0);
    this.#hh = null;
    this.#clientPub = null;
    this.#pending = false;
  }

  #isClosed(): boolean {
    return this.#stage === "closed";
  }
}
