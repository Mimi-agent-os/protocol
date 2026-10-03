import assert from "node:assert/strict";
import { test } from "node:test";

import { parseEnvelope, REPLY_OF } from "../src/index.ts";

test("the envelope parser requires a payload field but leaves its value opaque", () => {
    const payload = { messages: "domain validation happens later" };
    assert.deepEqual(parseEnvelope({ id: "r1", type: "chat", payload }), {
        id: "r1",
        type: "chat",
        payload,
    });
    assert.equal(parseEnvelope({ id: "r1", type: "chat" }), null);
    assert.deepEqual(parseEnvelope({ id: "r1", type: "chat", payload: null }), {
        id: "r1",
        type: "chat",
        payload: null,
    });
    assert.deepEqual(parseEnvelope({ id: "r1", type: "chat", payload: undefined }), {
        id: "r1",
        type: "chat",
        payload: undefined,
    });

    assert.equal(parseEnvelope({ id: "r1", type: "chat_ok", status: "ok" }), null);
    assert.deepEqual(parseEnvelope({ id: "r1", type: "chat_ok", status: "ok", payload: null }), {
        id: "r1",
        type: "chat_ok",
        status: "ok",
        payload: null,
    });
    assert.deepEqual(parseEnvelope({ id: "r1", type: "chat_ok", status: "ok", payload: undefined }), {
        id: "r1",
        type: "chat_ok",
        status: "ok",
        payload: undefined,
    });
});

test("the envelope parser rejects malformed identities and statuses and strips unknown fields", () => {
    const malformed: unknown[] = [
        undefined,
        null,
        false,
        0,
        "frame",
        [],
        {},
        { id: "r1", payload: {} },
        { type: "chat", payload: {} },
        { id: "", type: "chat", payload: {} },
        { id: 1, type: "chat", payload: {} },
        { id: "r1", type: "", payload: {} },
        { id: "r1", type: 1, payload: {} },
        { id: "r1", type: "chat", status: undefined, payload: {} },
        { id: "r1", type: "chat", status: "pending", payload: {} },
    ];
    for (const [index, value] of malformed.entries()) {
        assert.equal(parseEnvelope(value), null, `accepted malformed envelope ${index}`);
    }

    const payload = {};
    assert.deepEqual(parseEnvelope({ id: "r1", type: "chat", payload, ignored: "not on the wire" }), {
        id: "r1",
        type: "chat",
        payload,
    });
});

test("the envelope parser accepts optional deadlines only when they are finite nonnegative numbers", () => {
    const request = { id: "r1", type: "invoke", payload: {} };
    assert.deepEqual(parseEnvelope(request), request);
    assert.deepEqual(parseEnvelope({ ...request, deadline: 0 }), { ...request, deadline: 0 });
    for (const deadline of [-1, NaN, Infinity, -Infinity, "30", null]) {
        assert.equal(parseEnvelope({ ...request, deadline }), null, `accepted invalid deadline ${deadline}`);
    }
});

test("the envelope parser preserves valid reply errors and rejects malformed ones", () => {
    for (const status of ["error", "denied", "timeout"] as const) {
        const detail = { retry: false };
        assert.deepEqual(
            parseEnvelope({ id: "r1", type: "future_reply", status, error: { message: "failed", code: "E_FUTURE", detail } }),
            { id: "r1", type: "future_reply", status, error: { message: "failed", code: "E_FUTURE", detail } },
        );
    }
    assert.deepEqual(parseEnvelope({ id: "r1", type: "result", status: "error", error: { message: "failed" } }), {
        id: "r1",
        type: "result",
        status: "error",
        error: { message: "failed" },
    });
    for (const error of [{}, { message: 1 }, { message: "failed", code: 1 }, { message: "failed", code: null }]) {
        assert.equal(parseEnvelope({ id: "r1", type: "result", status: "error", error }), null);
    }
});

test("the envelope parser retains unknown request and reply names for their handlers", () => {
    assert.deepEqual(parseEnvelope({ id: "r2", type: "new_future_request", payload: {} }), {
        id: "r2",
        type: "new_future_request",
        payload: {},
    });
    assert.deepEqual(parseEnvelope({ id: "r2", type: "new_future_reply", status: "ok", payload: {} }), {
        id: "r2",
        type: "new_future_reply",
        status: "ok",
        payload: {},
    });
});

test("the envelope parser ignores inherited optionals and rejects inherited required fields", () => {
    const inheritedIdentity = Object.assign(Object.create({ id: "r1", type: "invoke" }) as object, { payload: {} });
    assert.equal(parseEnvelope(inheritedIdentity), null);

    const request = Object.assign(Object.create({ status: "ok", deadline: 99 }) as object, {
        id: "r1",
        type: "invoke",
        payload: {},
    });
    assert.deepEqual(parseEnvelope(request), { id: "r1", type: "invoke", payload: {} });

    const inheritedError = Object.assign(Object.create({ message: "failed" }) as object, {});
    assert.equal(parseEnvelope({ id: "r1", type: "result", status: "error", error: inheritedError }), null);
});

test("REPLY_OF answers its own request names only, never an inherited member", () => {
    assert.equal(Object.getPrototypeOf(REPLY_OF), null);
    const lookup = REPLY_OF as Record<string, string | undefined>;
    assert.equal(lookup["hello"], "hello_ok");
    for (const inherited of ["constructor", "toString", "hasOwnProperty", "valueOf", "__proto__"]) {
        assert.equal(lookup[inherited] ?? "result", "result", inherited);
    }
});
