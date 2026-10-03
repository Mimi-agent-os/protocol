import type { AvatarType } from "./wire/handshake.ts";

/** The gateway's one port: registered range, below ephemeral. */
export const GATEWAY_PORT = 46464;

/** Bump only when a frame or payload change is incompatible — additive optional fields do not. */
export const PROTOCOL_VERSION = 1;

/** A pairing device name is at most this many code points. */
export const MAX_DEVICE_NAME_CHARS = 64;

/** Agent-name charset, unanchored: a lowercase slug of letters, digits, `_` and `-`, first char a
 *  letter, carrying the device-name length bound (an agent enrolls under this name). */
export const AGENT_NAME_SOURCE = `[a-z][a-z0-9_-]{0,${MAX_DEVICE_NAME_CHARS - 1}}`;

const AGENT_NAME = new RegExp(`^${AGENT_NAME_SOURCE}$`);

export const isAgentName = (name: string): boolean => AGENT_NAME.test(name);

export const AGENT_DESCRIPTION_MAX = 300;

// takes trimmed text: the agent and the gateway both trim, check, and keep what they checked
export const isAgentDescription = (text: string): boolean =>
    text !== "" && text.length <= AGENT_DESCRIPTION_MAX && !/[\r\n\u2028\u2029]/.test(text);

/** An agent avatar's raw size cap; describe carries it base64, counted against the 512 KiB an agent may send on connect. */
export const AVATAR_MAX_BYTES = 64 * 1024;

// by magic bytes, never by file name; raster only, since an SVG can carry script
export function avatarType(bytes: Uint8Array): AvatarType | undefined {
    const at = (offset: number, ascii: string): boolean => [...ascii].every((c, i) => bytes[offset + i] === c.charCodeAt(0));
    if (at(0, "\x89PNG\r\n\x1a\n")) return "image/png";
    if (at(0, "\xff\xd8\xff")) return "image/jpeg";
    if (at(0, "RIFF") && at(8, "WEBP")) return "image/webp";
    return undefined;
}
