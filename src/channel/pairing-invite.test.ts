import { x25519 } from "@noble/curves/ed25519.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { gatewayId, makeInviteUri, newInvite, parseInviteUri } from "./pairing-invite.ts";

const gwPriv = new Uint8Array(32).fill(11);
const gwPub = x25519.getPublicKey(gwPriv);
const sampleInvite = { id: "ABCDEFGHIJ", secret: new Uint8Array(32).fill(7), expiresAt: 120_000 };

test("new invites have a two-minute lifetime and canonical random fields", () => {
  const invite = newInvite(0);
  assert.equal(invite.expiresAt, 120_000);
  assert.equal(invite.secret.length, 32);
  assert.match(invite.id, /^[A-Z2-7]{10}$/);
});

test("invite uris round-trip in any parameter order", () => {
  const uri = makeInviteUri(gwPub, sampleInvite);
  const parsed = parseInviteUri(uri);
  assert.deepEqual(parsed.gwPub, gwPub);
  assert.equal(parsed.id, sampleInvite.id);
  assert.deepEqual(parsed.secret, sampleInvite.secret);

  const [gwPart, idPart, secretPart] = uri.slice("mimi://pair/v2?".length).split("&");
  if (!gwPart || !idPart || !secretPart) throw new Error("malformed test invite");
  assert.deepEqual(parseInviteUri(`mimi://pair/v2?${secretPart}&${idPart}&${gwPart}`), parsed);
});

test("an invite uri carries the gateway address as an optional canonical origin", () => {
  for (const address of ["http://100.64.1.2:46464", "https://gw.tail1234.ts.net", "http://[fd7a:115c:a1e0::1]:46464"]) {
    const uri = makeInviteUri(gwPub, sampleInvite, address);
    assert.match(uri, /&at=http/);
    const parsed = parseInviteUri(uri);
    assert.equal(parsed.address, address);
    assert.equal(parsed.id, sampleInvite.id);
    assert.deepEqual(parsed.secret, sampleInvite.secret);
    const [gwPart, idPart, secretPart, atPart] = uri.slice("mimi://pair/v2?".length).split("&");
    assert.equal(parseInviteUri(`mimi://pair/v2?${atPart}&${secretPart}&${idPart}&${gwPart}`).address, address);
  }
  assert.equal(parseInviteUri(makeInviteUri(gwPub, sampleInvite)).address, undefined);
  for (const bad of ["ws://1.2.3.4:46464", "http://1.2.3.4:46464/channel", "http://1.2.3.4:80", "http://u:p@1.2.3.4", "http://1.2.3.4/", `http://${"a".repeat(200)}.io`, "100.64.1.2:46464"]) {
    assert.throws(() => makeInviteUri(gwPub, sampleInvite, bad), /address/, bad);
  }
  const uri = makeInviteUri(gwPub, sampleInvite);
  for (const at of ["http://1.2.3.4:46464", "http%3a%2f%2f1.2.3.4%3a46464", "%E0%A4%A", encodeURIComponent("http://1.2.3.4:46464/x")]) {
    assert.throws(() => parseInviteUri(`${uri}&at=${at}`), /address/, at);
  }
  assert.throws(() => parseInviteUri(`${uri}&at=${encodeURIComponent("http://1.2.3.4:1")}&at=${encodeURIComponent("http://1.2.3.4:2")}`), /uri/);
});

test("parseInviteUri rejects malformed and non-canonical inputs", async (t) => {
  const uri = makeInviteUri(gwPub, sampleInvite);
  const [gwPart, , secretPart] = uri.slice("mimi://pair/v2?".length).split("&");
  if (!gwPart || !secretPart) throw new Error("malformed test invite");
  const gw = gwPart.slice("gw=".length);
  const secret = secretPart.slice("s=".length);
  const noncanonicalGw = `${gw.slice(0, -1)}${gw.endsWith("A") ? "B" : "R"}`;
  const noncanonicalSecret = `${secret.slice(0, -1)}${secret.endsWith("A") ? "B" : "R"}`;
  const cases = [
    ["wrong scheme", uri.replace("mimi://", "https://"), /uri/],
    ["unknown field", uri.replace("&s=", "&x="), /uri/],
    ["short id", uri.replace(`id=${sampleInvite.id}`, "id=ABCDEFG"), /id/],
    ["long id", uri.replace(`id=${sampleInvite.id}`, `id=${sampleInvite.id}A`), /id/],
    ["invalid id alphabet", uri.replace(`id=${sampleInvite.id}`, `id=${sampleInvite.id.slice(0, 9)}0`), /id/],
    ["short secret", uri.replace(secretPart, "s=ABCDEFGHIJKLMNOP"), /key/],
    ["invalid base32 alphabet", uri.replace(gwPart, `gw=a${gw.slice(1)}`), /base32/],
    ["missing query", "mimi://pair/v2", /uri/],
    ["old version", uri.replace("/v2?", "/v1?"), /uri/],
    ["extra field", `${uri}&x=A`, /uri/],
    ["duplicate id", `${uri}&id=${sampleInvite.id}`, /uri/],
    ["duplicate gateway", `mimi://pair/v2?${gwPart}&${gwPart}&${secretPart}`, /uri/],
    ["overlong uri", `mimi://pair/v2?${"A".repeat(600)}`, /uri/],
    ["non-canonical gateway", uri.replace(gwPart, `gw=${noncanonicalGw}`), /canonical/],
    ["non-canonical secret", uri.replace(secretPart, `s=${noncanonicalSecret}`), /canonical/],
  ] as const;

  for (const [name, malformed, expected] of cases) {
    await t.test(name, () => assert.throws(() => parseInviteUri(malformed), expected));
  }
});

test("makeInviteUri rejects malformed keys and ids", () => {
  for (const [make, expected] of [
    [() => makeInviteUri(gwPub.subarray(1), sampleInvite), /key/],
    [() => makeInviteUri(gwPub, { ...sampleInvite, secret: sampleInvite.secret.subarray(1) }), /key/],
    [() => makeInviteUri(gwPub, { ...sampleInvite, id: `${sampleInvite.id}A` }), /id/],
  ] as const) {
    assert.throws(make, expected);
  }
});

test("gatewayId matches an independent SHA-256 and base32 vector", () => {
  const id = gatewayId(gwPub);
  const digest = createHash("sha256").update("mimi/id/v1").update(gwPub).digest();
  const bits = [...digest].map((b) => b.toString(2).padStart(8, "0")).join("").padEnd(260, "0");
  let expected = "";
  for (let i = 0; i < 260; i += 5) expected += "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[parseInt(bits.slice(i, i + 5), 2)];
  assert.equal(id, expected);
  assert.equal(id, "T4V3AH346OYUMG7BP4ILZPYKBVW7BXMP2OTF4FITLYFDPMIUPJBA");
});
