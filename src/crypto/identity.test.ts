import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { allPerms, fingerprint, noPerms, readPerms } from "./identity.ts";

const KEY = Buffer.from("a public key, pretend it is 1184 bytes", "utf8");
const KEY_B64 = KEY.toString("base64");
const DIGEST = createHash("sha256").update(KEY).digest("hex");

test("fingerprint is sha256 of the key, 8 groups of 4 hex", () => {
    assert.equal(fingerprint(KEY), `sha256:${DIGEST.slice(0, 32).match(/.{4}/g)?.join("-") ?? ""}`);
});

test("bytes and base64 fingerprint identically, and malformed base64 is refused", () => {
    assert.equal(fingerprint(KEY_B64), fingerprint(KEY));
    for (const malformed of ["!!!!", "YQ", "YR==", " YQ==\n"]) assert.throws(() => fingerprint(malformed));
});

test("perms read strictly: anything not exactly true is false", () => {
    assert.deepEqual(readPerms({ delegate: true, discoverable: 1 }), {
        delegate: true,
        discoverable: false,
    });
    assert.deepEqual(readPerms(null), noPerms());
    assert.deepEqual(readPerms([true, true]), noPerms());
    assert.deepEqual(readPerms(allPerms()), allPerms());
    assert.deepEqual(readPerms(Object.create({ delegate: true, discoverable: true })), noPerms());

    let reads = 0;
    const hidden: Record<string, unknown> = {};
    Object.defineProperty(hidden, "delegate", { enumerable: false, value: true });
    Object.defineProperty(hidden, "discoverable", { enumerable: true, get: () => (++reads, true) });
    assert.deepEqual(readPerms(hidden), noPerms());
    assert.equal(reads, 0);
});
