// QR/link pairing machines over Noise_IKpsk2_25519_ChaChaPoly_SHA256.
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { equalBytes } from "@noble/ciphers/utils.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import { MAX_DEVICE_NAME_CHARS } from "../constants.ts";
import { Handshake, type CipherState } from "./noise.ts";
import { frame, FrameDecodeError, FrameDecoder } from "./frame.ts";
import { parseInviteUri, type Invite } from "./pairing-invite.ts";

export type ResponderEvent =
  | { type: "enrolled"; clientPub: Uint8Array; deviceName: string; sas: string }
  // Not terminal: the abandoned attempt keeps its spent debit, the invite stays open for the rest of its window.
  | { type: "pending_expired" }
  | { type: "closed"; reason: "bad" | "debits" | "timeout" };

export type InitiatorEvent = { type: "enrolled"; sas: string } | { type: "closed" };

interface PendingEnrollment {
  send: CipherState;
  recv: CipherState;
  clientPub: Uint8Array;
  sas: string;
  deadline: number;
  requestKey: string;
  reply: Uint8Array;
}

const CONFIRM_TTL = 10_000;
const MAX_DEBITS = 3;

const utf8 = new TextEncoder();
const utf8d = new TextDecoder();
const PROLOGUE = utf8.encode("mimi/pair/v2");
const SAS_INFO = utf8.encode("mimi/approve-sas");
const AUTH_INFO = utf8.encode("mimi/pair-auth/v2");
const DUMMY_INFO = utf8.encode("mimi/pair-dummy/v2");
const MAX_DEVICE_NAME_BYTES = 256;
const AUTH_LENGTH = 32;
const NOISE_MSG1_MIN = 96;
const INITIAL_FRAME_MIN = AUTH_LENGTH + NOISE_MSG1_MIN;
const PAIRING_FRAME_MAX = 512;
const MSG2_LENGTH = 48;
const PAIR_OK_LENGTH = 31;

export function deriveSas(enrollmentHash: Uint8Array): string {
  const okm = hkdf(sha256, enrollmentHash, new Uint8Array(0), SAS_INFO, 8);
  const n = new DataView(okm.buffer, okm.byteOffset, 8).getBigUint64(0, false);
  okm.fill(0);
  return String(n % 1_000_000n).padStart(6, "0");
}

function pairAuthenticator(secret: Uint8Array, message: Uint8Array): Uint8Array {
  return hmac(sha256, secret, concatBytes(AUTH_INFO, message));
}

function dummyReply(secret: Uint8Array, request: Uint8Array): Uint8Array {
  const first = hmac(sha256, secret, concatBytes(DUMMY_INFO, Uint8Array.of(0), request));
  const second = hmac(sha256, secret, concatBytes(DUMMY_INFO, Uint8Array.of(1), request));
  const body = concatBytes(first, second.subarray(0, 16));
  try {
    return frame(body);
  } finally {
    first.fill(0);
    second.fill(0);
    body.fill(0);
  }
}

function validDeviceName(value: unknown): value is string {
  if (typeof value !== "string") return false;
  let chars = 0;
  for (const _ of value) if (++chars > MAX_DEVICE_NAME_CHARS) return false;
  return utf8.encode(value).length <= MAX_DEVICE_NAME_BYTES;
}

export class PairingResponder {
  #s: Uint8Array;
  #invite: Invite | null;
  #now: () => number;
  #frames = new FrameDecoder();
  #debits = 0;
  #pending: PendingEnrollment | null = null;

  public constructor(o: { s: Uint8Array; invite: Invite; now(): number }) {
    this.#s = o.s.slice();
    this.#invite = { id: o.invite.id, secret: o.invite.secret.slice(), expiresAt: o.invite.expiresAt };
    this.#now = o.now;
    this.#frames.setBounds(INITIAL_FRAME_MIN, PAIRING_FRAME_MAX);
  }

  public feed(bytes: Uint8Array): { out: Uint8Array[]; events: ResponderEvent[] } {
    if (this.#invite === null) return { out: [], events: [] };
    const out: Uint8Array[] = [];
    const events: ResponderEvent[] = [];
    try {
      for (const msg of this.#frames.feed(bytes)) {
        this.#frame(msg, out, events);
        if (this.#invite === null || events.at(-1)?.type === "closed") break;
      }
    } catch (error) {
      if (error instanceof FrameDecodeError) {
        // A bad length closes this byte stream, not the reusable invite.
        this.#frames.clear();
        this.#frames.setBounds(this.#pending === null ? INITIAL_FRAME_MIN : 16, PAIRING_FRAME_MAX);
        out.length = 0;
        events.push({ type: "closed", reason: "bad" });
      } else {
        this.#finish();
        throw error;
      }
    }
    return { out, events };
  }

  public expire(): ResponderEvent[] {
    const invite = this.#invite;
    if (invite === null) return [];
    const now = this.#now();
    if (now >= invite.expiresAt) {
      this.#finish();
      return [{ type: "closed", reason: "timeout" }];
    }
    if (this.#pending !== null && now >= this.#pending.deadline) {
      this.#clearPending();
      this.#frames.setBounds(INITIAL_FRAME_MIN, PAIRING_FRAME_MAX);
      return [{ type: "pending_expired" }];
    }
    return [];
  }

  public destroy(): void {
    this.#finish();
  }

  #frame(msg: Uint8Array, out: Uint8Array[], events: ResponderEvent[]): void {
    events.push(...this.expire());
    const invite = this.#invite;
    if (invite === null) return;
    const now = this.#now();
    const key = bytesToHex(sha256(concatBytes(utf8.encode(invite.id), msg)));
    if (this.#pending?.requestKey === key) {
      out.push(this.#pending.reply.slice());
      return;
    }
    if (this.#pending !== null) {
      let pt: Uint8Array | null = null;
      try {
        pt = this.#pending.recv.decrypt(msg);
      } catch {
        pt = null;
      }
      if (pt !== null) {
        let name: string | null = null;
        try {
          const obj = JSON.parse(utf8d.decode(pt));
          if (obj.t === "pair_confirm" && validDeviceName(obj.name)) name = obj.name;
        } catch {
          name = null;
        }
        if (name === null) {
          this.#clearPending();
          this.#frames.setBounds(INITIAL_FRAME_MIN, PAIRING_FRAME_MAX);
          events.push({ type: "closed", reason: "bad" });
          return;
        }
        const enrolled = { type: "enrolled" as const, clientPub: this.#pending.clientPub.slice(), deviceName: name, sas: this.#pending.sas };
        out.push(frame(this.#pending.send.encrypt(utf8.encode(JSON.stringify({ t: "pair_ok" })))));
        events.push(enrolled);
        this.#finish();
        return;
      }
    }
    if (msg.length < INITIAL_FRAME_MIN) {
      events.push({ type: "closed", reason: "bad" });
      return;
    }
    const message = msg.subarray(AUTH_LENGTH);
    const expected = pairAuthenticator(invite.secret, message);
    let authenticated: boolean;
    try {
      authenticated = equalBytes(msg.subarray(0, AUTH_LENGTH), expected);
    } finally {
      expected.fill(0);
    }
    if (!authenticated) {
      out.push(dummyReply(invite.secret, msg));
      return;
    }
    if (this.#debits >= MAX_DEBITS) {
      out.push(dummyReply(invite.secret, msg));
      this.#finish();
      events.push({ type: "closed", reason: "debits" });
      return;
    }
    this.#debits += 1;
    const hs = new Handshake({ pattern: "IKpsk2", initiator: false, prologue: PROLOGUE, s: this.#s, psks: [invite.secret] });
    let inviteId: unknown = null;
    try {
      const payload = hs.readMessage(message);
      const parsed = JSON.parse(utf8d.decode(payload));
      inviteId = parsed.invite;
    } catch {
      hs.destroy();
      if (this.#pending === null) events.push({ type: "closed", reason: "bad" });
      return;
    }
    let reply: Uint8Array;
    try {
      reply = frame(hs.writeMessage());
    } catch (error) {
      hs.destroy();
      throw error;
    }
    out.push(reply);
    if (inviteId !== invite.id || this.#pending !== null) {
      hs.destroy();
      return;
    }
    let clientPub: Uint8Array;
    let sas: string;
    let send: CipherState;
    let recv: CipherState;
    try {
      clientPub = hs.remoteStatic!;
      sas = deriveSas(hs.handshakeHash);
      ({ send, recv } = hs.split());
    } finally {
      hs.destroy();
    }
    this.#pending = {
      send,
      recv,
      clientPub,
      sas,
      deadline: now + CONFIRM_TTL,
      requestKey: key,
      reply: reply.slice(),
    };
    this.#frames.setBounds(16, PAIRING_FRAME_MAX);
  }

  #clearPending(): void {
    const pending = this.#pending;
    if (pending === null) return;
    pending.send.destroy();
    pending.recv.destroy();
    pending.clientPub.fill(0);
    pending.reply.fill(0);
    this.#pending = null;
  }

  #finish(): void {
    this.#frames.clear();
    this.#clearPending();
    this.#s.fill(0);
    this.#invite?.secret.fill(0);
    this.#invite = null;
  }
}

export class PairingInitiator {
  #hs: Handshake | null;
  #inviteId: string;
  #inviteSecret: Uint8Array | null;
  #deviceName: string;
  #frames = new FrameDecoder();
  #recv: CipherState | null = null;
  #sas = "";
  #state: "idle" | "msg2" | "ok" | "finished" = "idle";

  public constructor(o: { s: Uint8Array; uri: string; deviceName: string }) {
    if (!validDeviceName(o.deviceName)) throw new Error("invalid device name");
    const { gwPub, id, secret } = parseInviteUri(o.uri);
    this.#inviteId = id;
    this.#inviteSecret = secret;
    this.#deviceName = o.deviceName;
    try {
      this.#hs = new Handshake({ pattern: "IKpsk2", initiator: true, prologue: PROLOGUE, s: o.s, rs: gwPub, psks: [secret] });
    } catch (error) {
      secret.fill(0);
      this.#inviteSecret = null;
      throw error;
    }
    this.#frames.setBounds(MSG2_LENGTH, MSG2_LENGTH);
  }

  public start(): Uint8Array[] {
    if (this.#state !== "idle") throw new Error("already started");
    this.#state = "msg2";
    try {
      const message = this.#hs!.writeMessage(utf8.encode(JSON.stringify({ invite: this.#inviteId })));
      const authenticator = pairAuthenticator(this.#inviteSecret!, message);
      try {
        return [frame(concatBytes(authenticator, message))];
      } finally {
        authenticator.fill(0);
        this.#inviteSecret!.fill(0);
        this.#inviteSecret = null;
      }
    } catch (error) {
      this.#finish();
      throw error;
    }
  }

  public feed(bytes: Uint8Array): { out: Uint8Array[]; events: InitiatorEvent[] } {
    if (this.#state === "finished") return { out: [], events: [] };
    if (this.#state === "idle") throw new Error("pairing not started");
    const out: Uint8Array[] = [];
    const events: InitiatorEvent[] = [];
    try {
      for (const msg of this.#frames.feed(bytes)) {
        if (this.#state === "msg2") {
          const hs = this.#hs!;
          try {
            hs.readMessage(msg);
          } catch {
            this.#finish();
            out.length = 0;
            events.push({ type: "closed" });
            break;
          }
          const { send, recv } = hs.split();
          this.#recv = recv;
          try {
            this.#sas = deriveSas(hs.handshakeHash);
            hs.destroy();
            this.#hs = null;
            out.push(frame(send.encrypt(utf8.encode(JSON.stringify({ t: "pair_confirm", name: this.#deviceName })))));
          } finally {
            send.destroy();
          }
          this.#state = "ok";
          this.#frames.setBounds(PAIR_OK_LENGTH, PAIR_OK_LENGTH);
        } else if (this.#state === "ok") {
          try {
            const obj = JSON.parse(utf8d.decode(this.#recv!.decrypt(msg)));
            if (obj.t !== "pair_ok") throw new Error("unexpected reply");
          } catch {
            this.#finish();
            out.length = 0;
            events.push({ type: "closed" });
            break;
          }
          const sas = this.#sas;
          this.#finish();
          events.push({ type: "enrolled", sas });
          break;
        }
      }
    } catch (error) {
      this.#finish();
      out.length = 0;
      if (error instanceof FrameDecodeError) events.push({ type: "closed" });
      else throw error;
    }
    return { out, events };
  }

  public destroy(): void {
    this.#finish();
  }

  #finish(): void {
    this.#state = "finished";
    this.#frames.clear();
    this.#hs?.destroy();
    this.#recv?.destroy();
    this.#inviteSecret?.fill(0);
    this.#hs = null;
    this.#recv = null;
    this.#inviteSecret = null;
    this.#inviteId = "";
    this.#deviceName = "";
    this.#sas = "";
  }
}
