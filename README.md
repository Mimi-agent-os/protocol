# @mimi-os/protocol

[![CI](https://github.com/Mimi-agent-os/protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/Mimi-agent-os/protocol/actions/workflows/ci.yml)

The shared vocabulary of mimi-os, a personal agent runtime (a gateway, the agents that connect to it, and an app).
It defines the messages the gateway, agents and the app exchange, and the encrypted channel they travel on.
Every other mimi-os package builds on it; when you write an agent, the sdk uses it for you.

Requires Node.js 24 or newer and pnpm (`corepack enable pnpm`).

## What is in it

Message types and their parser, neutral LLM types (messages, tools, usage), the hash that chains an agent's
event log, and the secure channel core: Noise + ML-KEM-768 state machines that work purely on bytes. Each
message, hash and channel byte has one definition here. It depends on four exact-pinned `@noble/*` packages.

## In the workspace

Every `mimi-launch` profile (`server`, `agents`, `devkit`) clones it. It is the base of the workspace: sdk,
plugins, gateway, devkit and app link it as `link:../protocol`. Exports point at `dist/`, so consumers see a
`src/` change after `pnpm build` (`mimi-launch update` builds protocol first).

## Commands

```sh
pnpm build   # empty dist/, then tsc -p tsconfig.build.json into dist/
pnpm check   # tsc over src and test, no emit
pnpm test    # node --test "src/**/*.test.ts" "test/**/*.test.ts"
pnpm clean   # delete dist/
```

## What you import

Everything comes from one entry point, `@mimi-os/protocol`.

- Constants and LLM types: `PROTOCOL_VERSION`, `GATEWAY_PORT`, `isAgentName`, `Message`, `Tool`,
  `ToolCall`, `StreamEvent`, `Usage`.
- Messages: `parseEnvelope`, `REPLY_OF`, `RequestOf<K>`, `ReplyOf<K>`, a `*Payload` type per message.
- Event log and identity: `chainHash`, `GENESIS_HASH`, `foldEvents`, `sanitizeHistory`, `fingerprint`.
- Channel: `ClientSession`, `ServerSession`, `PairingInitiator`, `PairingResponder`, `newInvite`,
  `makeInviteUri`, `parseInviteUri`, `FLAG_END`, `AppStreamPort`.

The channel machines leave sockets to the caller: feed received bytes in, write every returned chunk out.

```ts
import { x25519 } from "@noble/curves/ed25519.js";
import { ClientSession, FLAG_END, parseEnvelope, PROTOCOL_VERSION, ServerSession } from "@mimi-os/protocol";

const gateway = x25519.keygen();
const device = x25519.keygen();
const client = new ClientSession({ s: device.secretKey, gatewayPub: gateway.publicKey, protocol: PROTOCOL_VERSION });
const server = new ServerSession({ s: gateway.secretKey, protocol: PROTOCOL_VERSION, lookup: () => "active" });

let toServer = client.start();
while (toServer.length > 0) {
    toServer = toServer.flatMap((bytes) => server.feed(bytes).out).flatMap((bytes) => client.feed(bytes).out);
}

const hello = { id: "1", type: "hello", payload: { agent: "hello" } };
const records = client.send({ stream: 0, flags: FLAG_END, payload: new TextEncoder().encode(JSON.stringify(hello)) });
for (const event of records.flatMap((bytes) => server.feed(bytes).events)) {
    if (event.type === "frame") console.log(parseEnvelope(JSON.parse(new TextDecoder().decode(event.frame.payload))));
}
```

## PROTOCOL_VERSION

The wire version, separate from the package version. It is 1, bumped by hand on an incompatible message
change; an added optional field keeps the version as it is. Both session machines take it as `protocol`
and, during the handshake, send `incompatible_protocol` to a peer on another version and close the session.

## Neighbours

- [launch](https://github.com/Mimi-agent-os/launch): the workspace and `mimi-launch`.
- [sdk](https://github.com/Mimi-agent-os/sdk): the library agents are written with.
- [gateway](https://github.com/Mimi-agent-os/gateway): the other end of every agent session.
- [app](https://github.com/Mimi-agent-os/app): the desktop and Android client, a device on the same channel.

Licensed under Apache-2.0, see LICENSE.
