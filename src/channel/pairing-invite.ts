import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, randomBytes } from "@noble/hashes/utils.js";

export interface Invite {
  id: string;
  secret: Uint8Array;
  expiresAt: number;
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const INVITE_TTL = 120_000;
const INVITE_URI_MAX = 512;
const ADDRESS_MAX = 200;
/** The router's path segment for an invite id — one owner for the shape. */
export const INVITE_ID_SOURCE = "[A-Z2-7]{10}";
const INVITE_ID = new RegExp(`^${INVITE_ID_SOURCE}$`);
const KEY_B32_LENGTH = 52;
const utf8 = new TextEncoder();

function validInviteId(id: string): boolean {
  return INVITE_ID.test(id);
}

function base32Encode(b: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of b) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32.charAt((value >>> (bits - 5)) & 31);
      bits -= 5;
    }
  }
  if (bits > 0) out += B32.charAt((value << (5 - bits)) & 31);
  return out;
}

function base32Decode(s: string): Uint8Array {
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s) {
    const v = B32.indexOf(ch);
    if (v < 0) throw new Error("invalid base32");
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
      value &= (1 << bits) - 1;
    }
  }
  const decoded = Uint8Array.from(out);
  if (value !== 0 || base32Encode(decoded) !== s) throw new Error("non-canonical base32");
  return decoded;
}

export function newInvite(now: number): Invite {
  return { id: base32Encode(randomBytes(10)).slice(0, 10), secret: randomBytes(32), expiresAt: now + INVITE_TTL };
}

// the address is a bare http(s) origin, the form a client dials: no path, no credentials, no default port
function validAddress(address: string): boolean {
  const url = URL.parse(address);
  return address.length <= ADDRESS_MAX && url !== null && (url.protocol === "http:" || url.protocol === "https:") && url.origin === address;
}

/** `address`: the gateway origin the redeeming client should dial, carried as the optional `at` parameter. */
export function makeInviteUri(gwPub: Uint8Array, invite: Invite, address?: string | undefined): string {
  if (gwPub.length !== 32 || invite.secret.length !== 32) throw new Error("malformed invite key");
  if (!validInviteId(invite.id)) throw new Error("malformed invite id");
  if (address !== undefined && !validAddress(address)) throw new Error("malformed invite address");
  const at = address === undefined ? "" : `&at=${encodeURIComponent(address)}`;
  return `mimi://pair/v2?gw=${base32Encode(gwPub)}&id=${invite.id}&s=${base32Encode(invite.secret)}${at}`;
}

export function parseInviteUri(uri: string): { gwPub: Uint8Array; id: string; secret: Uint8Array; address?: string | undefined } {
  if (typeof uri !== "string" || uri.length > INVITE_URI_MAX) throw new Error("malformed invite uri");
  const m = /^mimi:\/\/pair\/v2\?(.+)$/.exec(uri);
  if (!m) throw new Error("malformed invite uri");
  const params = new Map<string, string>();
  const parts = m[1]!.split("&");
  if (parts.length !== 3 && parts.length !== 4) throw new Error("malformed invite uri");
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq < 1) throw new Error("malformed invite uri");
    const key = part.slice(0, eq);
    if ((key !== "gw" && key !== "id" && key !== "s" && key !== "at") || params.has(key)) throw new Error("malformed invite uri");
    params.set(key, part.slice(eq + 1));
  }
  const gw = params.get("gw");
  const id = params.get("id");
  const s = params.get("s");
  const at = params.get("at");
  if (gw === undefined || id === undefined || s === undefined) throw new Error("malformed invite uri");
  if (!validInviteId(id)) throw new Error("malformed invite id");
  if (gw.length !== KEY_B32_LENGTH || s.length !== KEY_B32_LENGTH) throw new Error("malformed invite key");
  const gwPub = base32Decode(gw);
  const secret = base32Decode(s);
  if (gwPub.length !== 32 || secret.length !== 32) throw new Error("malformed invite key");
  let address: string | undefined;
  if (at !== undefined) {
    try {
      address = decodeURIComponent(at);
    } catch {
      throw new Error("malformed invite address");
    }
    if (!validAddress(address) || encodeURIComponent(address) !== at) throw new Error("malformed invite address");
  }
  return { gwPub, id, secret, address };
}

export function gatewayId(pub: Uint8Array): string {
  return base32Encode(sha256(concatBytes(utf8.encode("mimi/id/v1"), pub)));
}
