// Noise Protocol Framework rev 34, suite 25519_ChaChaPoly_SHA256: NN, XX, IK, IKpsk2, XXpsk3.
import { x25519 } from "@noble/curves/ed25519.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { concatBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export type NoisePattern = "NN" | "XX" | "IK" | "IKpsk2" | "XXpsk3";

export interface HandshakeOptions {
  pattern: NoisePattern;
  initiator: boolean;
  prologue?: Uint8Array;
  s?: Uint8Array;
  rs?: Uint8Array;
  psks?: Uint8Array[];
}

type Token = "e" | "s" | "ee" | "es" | "se" | "ss" | "psk";

interface PatternDef {
  preS: boolean;
  messages: Token[][];
}

const PATTERNS: Record<NoisePattern, PatternDef> = {
  NN: { preS: false, messages: [["e"], ["e", "ee"]] },
  XX: { preS: false, messages: [["e"], ["e", "ee", "s", "es"], ["s", "se"]] },
  IK: { preS: true, messages: [["e", "es", "s", "ss"], ["e", "ee", "se"]] },
  IKpsk2: { preS: true, messages: [["e", "es", "s", "ss"], ["e", "ee", "se", "psk"]] },
  XXpsk3: { preS: false, messages: [["e"], ["e", "ee", "s", "es"], ["s", "se", "psk"]] },
};

const EMPTY = new Uint8Array(0);
const NONCE_MAX = 2n ** 64n - 1n;

const TEST_ONLY = Symbol("deterministic Noise ephemeral");

interface TestOnlyOptions {
  token: typeof TEST_ONLY;
  ephemeral: Uint8Array;
}

// Noise HKDF is an HMAC chain, not RFC 5869 with info; HKDF2 is the first two outputs of HKDF3.
function hkdf(ck: Uint8Array, ikm: Uint8Array): [Uint8Array, Uint8Array, Uint8Array] {
  const temp = hmac(sha256, ck, ikm);
  try {
    const o1 = hmac(sha256, temp, Uint8Array.of(1));
    const o2 = hmac(sha256, temp, concatBytes(o1, Uint8Array.of(2)));
    const o3 = hmac(sha256, temp, concatBytes(o2, Uint8Array.of(3)));
    return [o1, o2, o3];
  } finally {
    temp.fill(0);
  }
}

export class CipherState {
  #k: Uint8Array;
  #n = 0n;
  #destroyed = false;

  public constructor(key: Uint8Array) {
    if (key.length !== 32) throw new Error("cipher key must be 32 bytes");
    this.#k = key.slice();
  }

  public encrypt(pt: Uint8Array, ad?: Uint8Array): Uint8Array {
    const ct = this.#aead(ad).encrypt(pt);
    this.#n += 1n;
    return ct;
  }

  // A failed decrypt throws before the counter advances.
  public decrypt(ct: Uint8Array, ad?: Uint8Array): Uint8Array {
    const pt = this.#aead(ad).decrypt(ct);
    this.#n += 1n;
    return pt;
  }

  public get key(): Uint8Array {
    this.#assertActive();
    return this.#k.slice();
  }

  public get nonce(): bigint {
    return this.#n;
  }

  public destroy(): void {
    if (this.#destroyed) return;
    this.#k.fill(0);
    this.#destroyed = true;
  }

  // AEAD nonce is 4 zero bytes then the counter as 64-bit little-endian.
  #aead(ad: Uint8Array | undefined) {
    this.#assertActive();
    if (this.#n >= NONCE_MAX) throw new Error("nonce exhausted");
    const nonce = new Uint8Array(12);
    new DataView(nonce.buffer).setBigUint64(4, this.#n, true);
    return chacha20poly1305(this.#k, nonce, ad);
  }

  #assertActive(): void {
    if (this.#destroyed) throw new Error("cipher state destroyed");
  }
}

class SymmetricState {
  ck: Uint8Array;
  h: Uint8Array;
  cs: CipherState | null = null;

  constructor(protocolName: string) {
    const name = utf8ToBytes(protocolName);
    this.h = name.length <= 32 ? concatBytes(name, new Uint8Array(32 - name.length)) : sha256(name);
    this.ck = this.h.slice();
  }

  mixHash(data: Uint8Array): void {
    this.h = sha256(concatBytes(this.h, data));
  }

  mixKey(ikm: Uint8Array): void {
    const [ck, tk, unused] = hkdf(this.ck, ikm);
    this.ck.fill(0);
    this.cs?.destroy();
    this.ck = ck;
    try {
      this.cs = new CipherState(tk);
    } finally {
      tk.fill(0);
      unused.fill(0);
    }
  }

  mixKeyAndHash(ikm: Uint8Array): void {
    const [ck, th, tk] = hkdf(this.ck, ikm);
    this.ck.fill(0);
    this.cs?.destroy();
    this.ck = ck;
    try {
      this.mixHash(th);
      this.cs = new CipherState(tk);
    } finally {
      th.fill(0);
      tk.fill(0);
    }
  }

  encryptAndHash(pt: Uint8Array): Uint8Array {
    const c = this.cs ? this.cs.encrypt(pt, this.h) : pt;
    this.mixHash(c);
    return c;
  }

  // The transcript absorbs the ciphertext as received; the pre-mix h is the AEAD ad.
  decryptAndHash(ct: Uint8Array): Uint8Array {
    const pt = this.cs ? this.cs.decrypt(ct, this.h) : ct.slice();
    this.mixHash(ct);
    return pt;
  }

  destroy(): void {
    this.ck.fill(0);
    this.cs?.destroy();
    this.cs = null;
  }
}

export class Handshake {
  #ss: SymmetricState;
  #initiator: boolean;
  #messages: Token[][];
  #hasPsk: boolean;
  #index = 0;
  #psks: Uint8Array[];
  #pskIndex = 0;
  #sPriv: Uint8Array | null;
  #sPub: Uint8Array | null;
  #ePriv: Uint8Array;
  #ePub: Uint8Array;
  #re: Uint8Array | null = null;
  #rs: Uint8Array | null = null;
  #split = false;
  #destroyed = false;

  public constructor(o: HandshakeOptions);
  public constructor(o: HandshakeOptions, testOnly?: TestOnlyOptions) {
    const def = PATTERNS[o.pattern];
    const ephemeral = testOnly?.token === TEST_ONLY ? testOnly.ephemeral : randomBytes(32);
    for (const k of [o.s, o.rs, ephemeral, ...(o.psks ?? [])]) {
      if (k !== undefined && k.length !== 32) throw new Error("keys and psks must be 32 bytes");
    }
    const pskCount = def.messages.flat().filter((t) => t === "psk").length;
    if ((o.psks?.length ?? 0) !== pskCount) throw new Error(`${o.pattern} takes exactly ${pskCount} psk(s)`);
    this.#ss = new SymmetricState(`Noise_${o.pattern}_25519_ChaChaPoly_SHA256`);
    this.#initiator = o.initiator;
    this.#messages = def.messages;
    this.#hasPsk = pskCount > 0;
    this.#psks = (o.psks ?? []).map((p) => p.slice());
    this.#sPriv = o.s ? o.s.slice() : null;
    this.#sPub = o.s ? x25519.getPublicKey(o.s) : null;
    this.#rs = o.rs ? o.rs.slice() : null;
    this.#ePriv = ephemeral.slice();
    this.#ePub = x25519.getPublicKey(this.#ePriv);
    this.#ss.mixHash(o.prologue ?? EMPTY);
    if (def.preS) {
      const pre = o.initiator ? this.#rs : this.#sPub;
      if (!pre) throw new Error(o.initiator ? `${o.pattern} initiator needs rs` : `${o.pattern} responder needs s`);
      this.#ss.mixHash(pre);
    }
  }

  public writeMessage(payload: Uint8Array = EMPTY): Uint8Array {
    this.#assertActive();
    const tokens = this.#messages[this.#index];
    if (!tokens) throw new Error("handshake already complete");
    if ((this.#index % 2 === 0) !== this.#initiator) throw new Error("peer writes this message");
    const parts: Uint8Array[] = [];
    for (const token of tokens) {
      switch (token) {
        case "e":
          parts.push(this.#ePub);
          this.#ss.mixHash(this.#ePub);
          if (this.#hasPsk) this.#ss.mixKey(this.#ePub);
          break;
        case "s":
          if (!this.#sPub) throw new Error("static key required");
          parts.push(this.#ss.encryptAndHash(this.#sPub));
          break;
        case "psk":
          this.#ss.mixKeyAndHash(this.#nextPsk());
          break;
        default:
          this.#mixDh(token);
      }
    }
    parts.push(this.#ss.encryptAndHash(payload));
    this.#index += 1;
    return concatBytes(...parts);
  }

  public readMessage(message: Uint8Array): Uint8Array {
    this.#assertActive();
    const tokens = this.#messages[this.#index];
    if (!tokens) throw new Error("handshake already complete");
    if ((this.#index % 2 === 0) === this.#initiator) throw new Error("we write this message");
    let off = 0;
    for (const token of tokens) {
      switch (token) {
        case "e":
          if (message.length < off + 32) throw new Error("truncated handshake message");
          this.#re = message.slice(off, off + 32);
          off += 32;
          this.#ss.mixHash(this.#re);
          if (this.#hasPsk) this.#ss.mixKey(this.#re);
          break;
        case "s": {
          const len = this.#ss.cs ? 48 : 32;
          if (message.length < off + len) throw new Error("truncated handshake message");
          this.#rs = this.#ss.decryptAndHash(message.subarray(off, off + len));
          off += len;
          break;
        }
        case "psk":
          this.#ss.mixKeyAndHash(this.#nextPsk());
          break;
        default:
          this.#mixDh(token);
      }
    }
    const payload = this.#ss.decryptAndHash(message.subarray(off));
    this.#index += 1;
    return payload;
  }

  public get complete(): boolean {
    return this.#index >= this.#messages.length;
  }

  public get handshakeHash(): Uint8Array {
    return this.#ss.h.slice();
  }

  public get remoteStatic(): Uint8Array | null {
    return this.#rs ? this.#rs.slice() : null;
  }

  public split(): { send: CipherState; recv: CipherState } {
    this.#assertActive();
    if (!this.complete) throw new Error("handshake not complete");
    if (this.#split) throw new Error("handshake already split");
    const [tk1, tk2, unused] = hkdf(this.#ss.ck, EMPTY);
    try {
      const result = this.#initiator
        ? { send: new CipherState(tk1), recv: new CipherState(tk2) }
        : { send: new CipherState(tk2), recv: new CipherState(tk1) };
      this.#split = true;
      this.#destroySecrets();
      return result;
    } finally {
      tk1.fill(0);
      tk2.fill(0);
      unused.fill(0);
    }
  }

  public destroy(): void {
    if (this.#destroyed) return;
    this.#destroyed = true;
    this.#destroySecrets();
  }

  #nextPsk(): Uint8Array {
    const psk = this.#psks[this.#pskIndex];
    if (!psk) throw new Error("psk missing");
    this.#pskIndex += 1;
    return psk;
  }

  #mixDh(token: "ee" | "es" | "se" | "ss"): void {
    let priv: Uint8Array | null;
    let pub: Uint8Array | null;
    switch (token) {
      case "ee":
        priv = this.#ePriv;
        pub = this.#re;
        break;
      case "ss":
        priv = this.#sPriv;
        pub = this.#rs;
        break;
      case "es":
        priv = this.#initiator ? this.#ePriv : this.#sPriv;
        pub = this.#initiator ? this.#rs : this.#re;
        break;
      case "se":
        priv = this.#initiator ? this.#sPriv : this.#ePriv;
        pub = this.#initiator ? this.#re : this.#rs;
        break;
    }
    if (!priv || !pub) throw new Error(`missing key material for ${token}`);
    const shared = x25519.getSharedSecret(priv, pub);
    try {
      this.#ss.mixKey(shared);
    } finally {
      shared.fill(0);
    }
  }

  #destroySecrets(): void {
    this.#ss.destroy();
    this.#sPriv?.fill(0);
    this.#sPriv = null;
    this.#ePriv.fill(0);
    for (const psk of this.#psks) psk.fill(0);
    this.#psks = [];
  }

  #assertActive(): void {
    if (this.#destroyed) throw new Error("handshake destroyed");
  }
}

/** Package-internal hook for byte-exact Noise vector tests. */
export function createDeterministicHandshake(options: HandshakeOptions, ephemeral: Uint8Array): Handshake {
  const InternalHandshake = Handshake as unknown as new (options: HandshakeOptions, testOnly: TestOnlyOptions) => Handshake;
  return new InternalHandshake(options, { token: TEST_ONLY, ephemeral });
}
