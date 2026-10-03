import { A2A_REPLIES, type A2aCatalog } from "../a2a.ts";
import { HANDSHAKE_REPLIES, type HandshakeCatalog } from "../handshake.ts";
import { MISC_REPLIES, type MiscCatalog, type NotifyFrame } from "../misc.ts";
import { SESSION_REPLIES, type SessionCatalog, type SessionChangedFrame } from "../session.ts";
import { WORK_REPLIES, type StreamFrame, type WorkCatalog } from "../work.ts";

import type { WireReply, WireRequest } from "./types.ts";

type Catalog = HandshakeCatalog & SessionCatalog & WorkCatalog & MiscCatalog & A2aCatalog;

const REPLIES = {
    ...HANDSHAKE_REPLIES,
    ...SESSION_REPLIES,
    ...WORK_REPLIES,
    ...MISC_REPLIES,
    ...A2A_REPLIES,
} as const satisfies Record<keyof Catalog, string>;

// Null prototype: an inherited `constructor`/`toString` must never answer a lookup by an incoming frame's untrusted `type`.
export const REPLY_OF: typeof REPLIES = Object.assign(Object.create(null), REPLIES);

export type RequestType = keyof Catalog;
export type ReplyType = (typeof REPLY_OF)[RequestType];

export type OkPayloadOf<K extends RequestType> = Catalog[K]["ok"];

// Mapping over K keeps each wire type paired with its payload when K is a union.
export type RequestOf<K extends RequestType = RequestType> = {
    [Type in K]: WireRequest<Type, Catalog[Type]["req"]>;
}[K];

export type ReplyOf<K extends RequestType = RequestType> = {
    [Type in K]: WireReply<(typeof REPLY_OF)[Type], Catalog[Type]["ok"]>;
}[K];

export type RequestFrame = RequestOf;
export type ReplyFrame = ReplyOf;

export type NoticeFrame = StreamFrame | SessionChangedFrame | NotifyFrame;

export const NOTICE_TYPES = ["stream", "session_changed", "notify"] as const satisfies readonly NoticeFrame["type"][];

export type Frame = RequestFrame | ReplyFrame | NoticeFrame;

export type FrameType = Frame["type"];
