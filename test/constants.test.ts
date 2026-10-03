import assert from "node:assert/strict";
import { test } from "node:test";

import { AGENT_DESCRIPTION_MAX, AGENT_NAME_SOURCE, avatarType, isAgentDescription, isAgentName } from "../src/index.ts";

test("an agent name is a bounded lowercase identifier — it enrolls as a pairing device name", () => {
    assert.ok(isAgentName("wren"));
    assert.ok(isAgentName("a".repeat(64)));
    assert.equal(isAgentName("a".repeat(65)), false);
    assert.equal(isAgentName(""), false);
    assert.equal(isAgentName("Wren"), false);
    assert.equal(isAgentName("9lives"), false);
    // dashes are allowed inside the name (like device/pin/view names), but not as the first char
    assert.ok(isAgentName("my-agent"));
    assert.ok(isAgentName("night-owl"));
    assert.equal(isAgentName("-lead"), false);
    // Routes and paths build their own matchers from the source, so the bound has to live in it.
    assert.equal(new RegExp(`^${AGENT_NAME_SOURCE}$`).test("a".repeat(65)), false);
});

test("an agent description is one non-empty line within the cap", () => {
    assert.ok(isAgentDescription("Keeps the owner's week in order."));
    assert.ok(isAgentDescription("x".repeat(AGENT_DESCRIPTION_MAX)));
    assert.equal(isAgentDescription("x".repeat(AGENT_DESCRIPTION_MAX + 1)), false);
    assert.equal(isAgentDescription(""), false);
    assert.equal(isAgentDescription("two\nlines"), false);
    assert.equal(isAgentDescription("two\rlines"), false);
    assert.equal(isAgentDescription("two\u2028lines"), false);
    assert.equal(isAgentDescription("two\u2029lines"), false);
});

test("an avatar's type comes from its magic bytes, and only PNG, JPEG and WebP have one", () => {
    const bytes = (...parts: Array<string | number[]>): Uint8Array =>
        Buffer.concat(parts.map((p) => (typeof p === "string" ? Buffer.from(p, "latin1") : Buffer.from(p))));
    assert.equal(avatarType(bytes([0x89], "PNG\r\n", [0x1a], "\n", [0, 0, 0, 13])), "image/png");
    assert.equal(avatarType(bytes([0xff, 0xd8, 0xff, 0xe0])), "image/jpeg");
    assert.equal(avatarType(bytes("RIFF", [0x24, 0, 0, 0], "WEBPVP8 ")), "image/webp");
    assert.equal(avatarType(bytes("RIFF", [0x24, 0, 0, 0], "WAVEfmt ")), undefined);
    assert.equal(avatarType(bytes('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')), undefined);
    assert.equal(avatarType(bytes("GIF89a")), undefined);
    assert.equal(avatarType(bytes([0x89], "PNG")), undefined, "a truncated signature is not a PNG");
    assert.equal(avatarType(new Uint8Array()), undefined);
});
