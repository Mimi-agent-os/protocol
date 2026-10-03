// One HTTP exchange per gateway-opened stream: a JSON header frame, body frames, credit frames.
import type { ChannelStreamFrame } from "./stream.ts";

export interface AppRequestHeader {
  t: "req";
  /** The catalog row's appId; the agent refuses anything but its own. */
  appId: string;
  method: string;
  /** Path inside the app, query included, the door's public prefix already stripped. */
  path: string;
  headers: Record<string, string | string[]>;
  mode?: "http" | "upgrade" | undefined;
}

export interface AppHeadReply {
  t: "head";
  status: number;
  headers: Record<string, string | string[]>;
}

export interface AppErrorReply {
  t: "error";
  code: AppStreamError;
  /** For the gateway log only — never rendered to a client. */
  detail?: string | undefined;
}

/** Only failures the agent can observe; the gateway's own refusals are never minted on the wire. */
export type AppStreamError = "no_app" | "unreachable" | "upstream_timeout" | "bad_upstream" | "refused_upgrade";

/** One gateway-opened stream as its writer holds it; the gateway and the SDK each implement it. */
export interface AppStreamPort {
  /** false = this stream's window is empty or the transport is behind: pause and register onDrain. */
  send(frame: Omit<ChannelStreamFrame, "stream">): boolean;
  onDrain(resume: () => void): void;
  reset(): void;
}

/** One header frame is one record: 48 KiB clears a doubled 16 KiB raw header set and still seals. */
export const APP_HEADER_MAX = 48 * 1024;
export const APP_HEADER_COUNT = 64;
export const APP_CHUNK = 16 * 1024;
/** Bytes one stream may hold unacknowledged in one direction: four chunks of credit. */
export const APP_WINDOW = 64 * 1024;
/** A zero-payload DATA frame credits exactly this many bytes: one per quantum consumed, never a reset to zero. */
export const APP_CREDIT = APP_WINDOW / 2;
/** The same window and quantum on the device plane (device ⇄ gateway), wide enough for a remote gateway's RTT. */
export const DEVICE_WINDOW = 512 * 1024;
export const DEVICE_CREDIT = DEVICE_WINDOW / 4;
export const APP_MAX_STREAMS = 64;
export const APP_PATH_MAX = 4 * 1024;
/** The upstream's deadline to answer with a head, held by the agent — it owns the socket; a head ends it. */
export const APP_IDLE_MS = 120_000;
/** The gateway's wait for a first reply frame; past APP_IDLE_MS so the agent's precise error wins. */
export const APP_HEAD_MS = 125_000;
/** How long one stream may sit on an empty window before it is reset. */
export const APP_STALL_MS = 30_000;

const METHOD = /^[A-Z]{1,16}$/;
/** An error reply's detail is a gateway log line, never rendered: this is all it may carry. */
export const APP_DETAIL_MAX = 200;
const ERROR_CODES: readonly AppStreamError[] = [
  "no_app",
  "unreachable",
  "upstream_timeout",
  "bad_upstream",
  "refused_upgrade",
];
const decoder = new TextDecoder("utf-8", { fatal: true });
const encoder = new TextEncoder();

function jsonObject(payload: Uint8Array): Record<string, unknown> {
  if (payload.length > APP_HEADER_MAX) throw new Error("app header too large");
  const value: unknown = JSON.parse(decoder.decode(payload));
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("app frame is not an object");
  return value as Record<string, unknown>;
}

function headerMap(value: unknown): Record<string, string | string[]> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("bad app headers");
  const entries = Object.entries(value);
  if (entries.length > APP_HEADER_COUNT) throw new Error("too many app headers");
  for (const [, v] of entries) {
    const ok = typeof v === "string" || (Array.isArray(v) && v.every((one) => typeof one === "string"));
    if (!ok) throw new Error("bad app header value");
  }
  return value as Record<string, string | string[]>;
}

export function decodeAppRequestHeader(payload: Uint8Array): AppRequestHeader {
  const { t, appId, method, path, headers, mode } = jsonObject(payload);
  if (t !== "req") throw new Error("not an app request");
  if (typeof appId !== "string" || appId.length === 0) throw new Error("bad appId");
  if (typeof method !== "string" || !METHOD.test(method)) throw new Error("bad method");
  if (typeof path !== "string" || !path.startsWith("/") || encoder.encode(path).length > APP_PATH_MAX) {
    throw new Error("bad path");
  }
  if (!(mode === undefined || mode === "http" || mode === "upgrade")) throw new Error("bad mode");
  return { t, appId, method, path, headers: headerMap(headers), mode };
}

export function decodeAppReply(payload: Uint8Array): AppHeadReply | AppErrorReply {
  const { t, status, headers, code, detail } = jsonObject(payload);
  if (t === "head") {
    if (typeof status !== "number" || !Number.isInteger(status) || status < 100 || status > 599) {
      throw new Error("bad status");
    }
    return { t, status, headers: headerMap(headers) };
  }
  if (t !== "error") throw new Error("not an app reply");
  const known = ERROR_CODES.find((one) => one === code);
  if (known === undefined) throw new Error("bad error code");
  if (detail !== undefined && (typeof detail !== "string" || detail.length > APP_DETAIL_MAX)) {
    throw new Error("bad error detail");
  }
  return { t, code: known, detail };
}
