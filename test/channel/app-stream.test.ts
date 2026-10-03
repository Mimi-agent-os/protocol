import { test } from "node:test";
import assert from "node:assert/strict";
import {
  APP_HEADER_COUNT,
  APP_HEADER_MAX,
  APP_PATH_MAX,
  FLAG_DATA,
  decodeAppReply,
  decodeAppRequestHeader,
} from "../../src/index.ts";
// The record ceiling is package-internal, so the size guard has to seal a real record.
import { CipherState } from "../../src/channel/noise.ts";
import { RecordLayer } from "../../src/channel/records.ts";
import { encodeStreamFrame } from "../../src/channel/stream.ts";

const utf8 = new TextEncoder();
const enc = (value: unknown): Uint8Array => utf8.encode(JSON.stringify(value));

const REQ = { t: "req", appId: "board", method: "POST", path: "/orders?page=2", headers: { host: "127.0.0.1:3377" } };

test("an app request header round-trips with and without a mode", () => {
  assert.deepEqual(decodeAppRequestHeader(enc(REQ)), { ...REQ, mode: undefined });
  assert.deepEqual(decodeAppRequestHeader(enc({ ...REQ, mode: "upgrade" })), { ...REQ, mode: "upgrade" });
  const multi = { ...REQ, headers: { "accept-encoding": ["gzip", "br"] } };
  assert.deepEqual(decodeAppRequestHeader(enc(multi)), { ...multi, mode: undefined });
});

test("an app reply round-trips a head and an error", () => {
  const head = { t: "head", status: 204, headers: { "set-cookie": ["a=1"] } };
  assert.deepEqual(decodeAppReply(enc(head)), head);
  assert.deepEqual(decodeAppReply(enc({ t: "error", code: "unreachable" })), {
    t: "error",
    code: "unreachable",
    detail: undefined,
  });
  assert.deepEqual(decodeAppReply(enc({ t: "error", code: "upstream_timeout", detail: "ECONNRESET" })), {
    t: "error",
    code: "upstream_timeout",
    detail: "ECONNRESET",
  });
});

test("an app request header is refused field by field", () => {
  assert.throws(() => decodeAppRequestHeader(Uint8Array.from([0xff, 0xfe, 0x7b])));
  assert.throws(() => decodeAppRequestHeader(enc([REQ])));
  assert.throws(() => decodeAppRequestHeader(enc(7)));
  assert.throws(() => decodeAppRequestHeader(utf8.encode("{")));
  assert.throws(() => decodeAppRequestHeader(enc({ ...REQ, t: "head" })));
  assert.throws(() => decodeAppRequestHeader(enc({ ...REQ, appId: "" })));
  assert.throws(() => decodeAppRequestHeader(enc({ ...REQ, method: "get" })));
  assert.throws(() => decodeAppRequestHeader(enc({ ...REQ, method: "A".repeat(17) })));
  assert.throws(() => decodeAppRequestHeader(enc({ ...REQ, path: "orders" })));
  assert.throws(() => decodeAppRequestHeader(enc({ ...REQ, path: `/${"a".repeat(APP_PATH_MAX)}` })));
  assert.throws(() => decodeAppRequestHeader(enc({ ...REQ, mode: "tunnel" })));
  assert.throws(() => decodeAppRequestHeader(enc({ ...REQ, headers: [] })));
  assert.throws(() => decodeAppRequestHeader(enc({ ...REQ, headers: { "x-n": 7 } })));
  assert.throws(() => decodeAppRequestHeader(enc({ ...REQ, headers: { "x-n": ["a", 7] } })));
  const many = Object.fromEntries(Array.from({ length: APP_HEADER_COUNT + 1 }, (_, i) => [`x-h${i}`, "v"]));
  assert.throws(() => decodeAppRequestHeader(enc({ ...REQ, headers: many })));
  const big = enc({ ...REQ, headers: { "x-pad": "a".repeat(APP_HEADER_MAX) } });
  assert.ok(big.length > APP_HEADER_MAX);
  assert.throws(() => decodeAppRequestHeader(big));
});

test("a path is bounded in bytes, not code points", () => {
  const twoByte = `/${"é".repeat(APP_PATH_MAX / 2)}`;
  assert.ok(twoByte.length < APP_PATH_MAX);
  assert.throws(() => decodeAppRequestHeader(enc({ ...REQ, path: twoByte })));
});

test("an app reply is refused field by field", () => {
  assert.throws(() => decodeAppReply(enc({ t: "head", status: 42, headers: {} })));
  assert.throws(() => decodeAppReply(enc({ t: "head", status: 200.5, headers: {} })));
  assert.throws(() => decodeAppReply(enc({ t: "head", status: 200, headers: "none" })));
  assert.throws(() => decodeAppReply(enc({ t: "req", status: 200, headers: {} })));
  assert.throws(() => decodeAppReply(enc({ t: "error", code: "forbidden" })));
  assert.throws(() => decodeAppReply(enc({ t: "error", code: "no_app", detail: "d".repeat(201) })));
  assert.throws(() => decodeAppReply(enc({ t: "head", status: 200, headers: { "x-pad": "a".repeat(APP_HEADER_MAX) } })));
});

test("a header frame of exactly APP_HEADER_MAX still seals into one record", () => {
  const layer = new RecordLayer(new CipherState(new Uint8Array(32).fill(1)), new CipherState(new Uint8Array(32).fill(2)));
  const payload = new Uint8Array(APP_HEADER_MAX).fill(0x61);
  const frame = encodeStreamFrame({ stream: 0xffffffff, flags: FLAG_DATA, payload });
  assert.doesNotThrow(() => layer.seal(frame));
});
