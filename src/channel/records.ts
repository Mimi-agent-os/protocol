// Encrypted record framing (u16 BE length || AEAD ciphertext).
import type { CipherState } from "./noise.ts";
import { frame, FrameDecoder } from "./frame.ts";

export const MAX_RECORD = 65535; // ciphertext ceiling incl. 16-byte tag (Noise message limit)
const TAG_LEN = 16;

export class RecordLayer {
  #send: CipherState;
  #recv: CipherState;
  #frames = new FrameDecoder(TAG_LEN);
  #destroyed = false;

  public constructor(send: CipherState, recv: CipherState) {
    this.#send = send;
    this.#recv = recv;
  }

  public install(send: CipherState, recv: CipherState): void {
    this.#assertActive();
    const replaced = new Set([this.#send, this.#recv]);
    this.#send = send;
    this.#recv = recv;
    replaced.delete(send);
    replaced.delete(recv);
    for (const state of replaced) state.destroy();
  }

  public seal(plaintext: Uint8Array): Uint8Array {
    this.#assertActive();
    if (plaintext.length > MAX_RECORD - TAG_LEN) throw new Error("record plaintext too large");
    return frame(this.#send.encrypt(plaintext));
  }

  // One record without its length prefix, so a caller can rekey between records.
  public open(ct: Uint8Array): Uint8Array {
    this.#assertActive();
    return this.#recv.decrypt(ct);
  }

  public feed(bytes: Uint8Array): Uint8Array[] {
    this.#assertActive();
    return Array.from(this.#frames.feed(bytes), (ct) => this.open(ct));
  }

  public destroy(): void {
    if (this.#destroyed) return;
    this.#destroyed = true;
    this.#send.destroy();
    this.#recv.destroy();
    this.#frames.clear();
  }

  #assertActive(): void {
    if (this.#destroyed) throw new Error("record layer destroyed");
  }
}
