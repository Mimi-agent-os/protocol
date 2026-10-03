import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { canon, chainHash, GENESIS_HASH } from "./hash.ts";
import type { HashableEvent } from "./hash.ts";

const sha256 = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

const UNICODE = "🦔 naïve — ok";

// built from code points so the two forms cannot collapse into one literal in this file
const PRECOMPOSED = "caf" + String.fromCharCode(0xe9);
const COMBINING = "cafe" + String.fromCharCode(0x301);

test("canon vectors: sorted keys over {seq, type, payload}", () => {
    assert.equal(
        canon({ seq: 1, type: "message", payload: { role: "user", content: "hi" } }),
        '{"payload":{"content":"hi","role":"user"},"seq":1,"type":"message"}',
    );
    assert.equal(
        canon({ seq: 7, type: "compaction", payload: { summary: "s", covers: [3, 6] } }),
        '{"payload":{"covers":[3,6],"summary":"s"},"seq":7,"type":"compaction"}',
    );
    assert.equal(
        canon({ seq: 2, type: "truncate", payload: { fromSeq: 5 } }),
        '{"payload":{"fromSeq":5},"seq":2,"type":"truncate"}',
    );
    assert.equal(
        canon({ seq: 3, type: "message", payload: null }),
        '{"payload":null,"seq":3,"type":"message"}',
    );
});

test("canon ignores key insertion order at every depth", () => {
    const a = { seq: 4, type: "message", payload: { b: { y: 1, x: 2 }, a: [{ q: 1, p: 2 }] } };
    const b = { payload: { a: [{ p: 2, q: 1 }], b: { x: 2, y: 1 } }, type: "message", seq: 4 };
    assert.equal(canon(a), canon(b));
    assert.equal(
        canon(a),
        '{"payload":{"a":[{"p":2,"q":1}],"b":{"x":2,"y":1}},"seq":4,"type":"message"}',
    );
});

test("canon fixes ECMAScript integer-key ordering in the hash format", () => {
    assert.equal(
        canon({ seq: 1, type: "message", payload: { "10": "ten", "2": "two", "01": "one" } }),
        '{"payload":{"2":"two","10":"ten","01":"one"},"seq":1,"type":"message"}',
    );
});

test("canon keeps array order — only object keys are sorted", () => {
    const forward = canon({ seq: 1, type: "message", payload: { xs: [3, 1, 2] } });
    const other = canon({ seq: 1, type: "message", payload: { xs: [2, 1, 3] } });
    assert.equal(forward, '{"payload":{"xs":[3,1,2]},"seq":1,"type":"message"}');
    assert.notEqual(forward, other);
});

test("a payload key named __proto__ is hashed, not swallowed by the prototype setter", () => {
    // a literal "__proto__" payload key must hash, not vanish into the prototype setter
    const a = JSON.parse('{"__proto__":{"a":1}}') as unknown;
    const b = JSON.parse('{"__proto__":{"b":2}}') as unknown;
    assert.equal(canon({ seq: 1, type: "message", payload: a }), '{"payload":{"__proto__":{"a":1}},"seq":1,"type":"message"}');
    assert.notEqual(
        chainHash("", { seq: 1, type: "message", payload: a }),
        chainHash("", { seq: 1, type: "message", payload: b }),
    );
    assert.notEqual(
        chainHash("", { seq: 1, type: "message", payload: a }),
        chainHash("", { seq: 1, type: "message", payload: {} }),
    );
    const nested = JSON.parse('{"role":"tool","content":"x","d":{"__proto__":{"s":true}}}') as unknown;
    assert.ok(canon({ seq: 2, type: "message", payload: nested }).includes('"__proto__":{"s":true}'));

    const nullPrototype = Object.assign(Object.create(null) as Record<string, unknown>, { z: 1, a: 2 });
    assert.equal(
        canon({ seq: 3, type: "message", payload: nullPrototype }),
        '{"payload":{"a":2,"z":1},"seq":3,"type":"message"}',
    );
});

test("canon separates null from a missing key", () => {
    assert.notEqual(
        chainHash("", { seq: 1, type: "message", payload: { role: "user", content: null } }),
        chainHash("", { seq: 1, type: "message", payload: { role: "user" } }),
    );
});

test("canon rejects values outside the JSON data model", () => {
    const invalid: unknown[] = [
        undefined,
        () => undefined,
        Symbol("value"),
        1n,
        Number.NaN,
        Number.POSITIVE_INFINITY,
        Number.NEGATIVE_INFINITY,
        { missing: undefined },
        [1, undefined],
        new Array(1),
        Object.assign([1], { extra: true }),
        new Date(0),
        new Uint8Array([1]),
        Object.create({ inherited: true }),
        { toJSON: () => ({ hidden: true }) },
    ];
    for (const payload of invalid) {
        assert.throws(() => canon({ seq: 1, type: "message", payload }), TypeError);
    }

    const symbolKey = { visible: true } as Record<PropertyKey, unknown>;
    symbolKey[Symbol("hidden")] = true;
    assert.throws(() => canon({ seq: 1, type: "message", payload: symbolKey }), TypeError);
});

test("canon rejects accessors without invoking them", () => {
    let reads = 0;
    const accessor = (): number => ++reads;
    const object: Record<string, unknown> = {};
    Object.defineProperty(object, "value", { enumerable: true, get: accessor });
    const array = [0];
    Object.defineProperty(array, "0", { enumerable: true, get: accessor });
    const event = { seq: 1, type: "message" } as { seq: number; type: string; payload: unknown };
    Object.defineProperty(event, "payload", { enumerable: true, get: accessor });

    assert.throws(() => canon({ seq: 1, type: "message", payload: object }), /data property/);
    assert.throws(() => canon({ seq: 1, type: "message", payload: array }), /data property/);
    assert.throws(() => canon(event), /data property/);
    assert.equal(reads, 0);
});

test("canon rejects hidden properties", () => {
    const hidden: Record<string, unknown> = {};
    Object.defineProperty(hidden, "value", { value: 1 });
    const hiddenArray = [1];
    Object.defineProperty(hiddenArray, "extra", { value: true });

    assert.throws(() => canon({ seq: 1, type: "message", payload: hidden }), /enumerable/);
    assert.throws(() => canon({ seq: 1, type: "message", payload: hiddenArray }), /enumerable/);
});

test("canon rejects cycles but allows repeated non-cyclic references", () => {
    const cyclic: { self?: unknown } = {};
    cyclic.self = cyclic;
    assert.throws(() => canon({ seq: 1, type: "message", payload: cyclic }), /cyclic/);

    const shared = { value: 1 };
    assert.equal(
        canon({ seq: 1, type: "message", payload: [shared, shared] }),
        '{"payload":[{"value":1},{"value":1}],"seq":1,"type":"message"}',
    );
});

test("canon has a deterministic depth limit instead of exhausting the call stack", () => {
    const depth = 100;
    let payload: unknown = "bottom";
    for (let i = 0; i < depth; i++) payload = [payload];

    const encoded = canon({ seq: 1, type: "message", payload });
    const shallow = canon({ seq: 1, type: "message", payload: "bottom" });
    assert.equal(encoded.length, shallow.length + depth * 2);
    assert.ok(encoded.startsWith('{"payload":[[['));
    assert.ok(encoded.endsWith(']]],"seq":1,"type":"message"}'));

    payload = [payload];
    assert.throws(
        () => canon({ seq: 1, type: "message", payload }),
        { name: "RangeError", message: "Canonical JSON exceeds maximum depth of 100" },
    );
});

test("storage metadata is not part of the event chain hash", () => {
    const event: HashableEvent = { seq: 1, type: "message", payload: { role: "user", content: "hi" } };
    const stored = { ...event, hash: "f".repeat(64), createdAt: 1_700_000_000_000 };
    assert.equal(chainHash(GENESIS_HASH, stored), chainHash(GENESIS_HASH, event));
});

test("canon preserves unicode without escaping it", () => {
    const ev: HashableEvent = { seq: 9, type: "message", payload: { t: UNICODE } };
    assert.equal(canon(ev), `{"payload":{"t":"${UNICODE}"},"seq":9,"type":"message"}`);
});

test("canon does not normalize unicode — different code points, different hash", () => {
    assert.notEqual(PRECOMPOSED, COMBINING);
    assert.equal(PRECOMPOSED.normalize("NFC"), COMBINING.normalize("NFC"));
    const a: HashableEvent = { seq: 1, type: "message", payload: { t: PRECOMPOSED } };
    const b: HashableEvent = { seq: 1, type: "message", payload: { t: COMBINING } };
    assert.notEqual(chainHash("", a), chainHash("", b));
});

test("chainHash = sha256(prevHash + canon(event)), genesis prev is the empty string", () => {
    const ev: HashableEvent = { seq: 1, type: "message", payload: { role: "user", content: "hi" } };
    assert.equal(GENESIS_HASH, "");
    assert.equal(chainHash(GENESIS_HASH, ev), sha256(canon(ev)));

    const prev = chainHash(GENESIS_HASH, ev);
    const next: HashableEvent = {
        seq: 2,
        type: "message",
        payload: { role: "assistant", content: "yo" },
    };
    assert.equal(chainHash(prev, next), sha256(prev + canon(next)));
});

test("hash depends on prevHash, seq and type — not only on payload", () => {
    const payload = { role: "user", content: "hi" };
    const base = chainHash("", { seq: 1, type: "message", payload });
    assert.notEqual(base, chainHash("ff", { seq: 1, type: "message", payload }));
    assert.notEqual(base, chainHash("", { seq: 2, type: "message", payload }));
    assert.notEqual(base, chainHash("", { seq: 1, type: "truncate", payload }));
});
