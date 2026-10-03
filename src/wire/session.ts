// The agent owns its sessions; the gateway mirrors an append-only, hash-chained event log.

import type { Message } from "../types.ts";
import type { WireNotice } from "./envelope/types.ts";

// numeric on purpose: session ids are structural (routes, cache keys), not display data
export type SessionId = number;

export interface CompactionPayload {
    summary: string;
    covers: [number, number];
}

export interface TruncatePayload {
    fromSeq: number;
}

export type EventBody =
    | { type: "message"; payload: Message }
    | { type: "compaction"; payload: CompactionPayload }
    | { type: "truncate"; payload: TruncatePayload };

export type StoredEvent = EventBody & {
    seq: number;
    hash: string;
    createdAt: number;
};

export interface SessionHead {
    session: SessionId;
    revision: number;
    headSeq: number;
    headHash: string;
}

export interface SessionHeadPayload {
    sessions: SessionId[];
}

// sessions the agent does not know are simply absent from `heads`
export interface SessionHeadOkPayload {
    heads: SessionHead[];
}

export interface EventsAfterPayload {
    session: SessionId;
    afterSeq: number;
    limit?: number;
}

export interface EventsAfterOkPayload {
    events: StoredEvent[];
    head: SessionHead;
    more: boolean;
}

export interface AppendPayload {
    session: SessionId;
    events: EventBody[];
}

export interface AppendOkPayload {
    head: SessionHead;
    seqs: number[];
}

export type SessionChangedFrame = WireNotice<"session_changed", SessionHead>;

export interface SessionCreatePayload {
    title?: string;
    titleByUser?: boolean;
}

export interface SessionCreateOkPayload {
    head: SessionHead;
}

export interface SessionListPayload {
    includeArchived?: boolean;
}

export interface SessionSummary {
    session: SessionId;
    title: string | null;
    titleByUser: boolean;
    archived: boolean;
    pinned: boolean;
    events: number;
    createdAt: number;
    updatedAt: number;
    head: SessionHead;
}

export interface SessionListOkPayload {
    sessions: SessionSummary[];
}

// metadata only: none of these move `revision`, so a valid cache stays valid
export interface SessionUpdatePayload {
    session: SessionId;
    title?: string;
    titleByUser?: boolean;
    archived?: boolean;
    pinned?: boolean;
}

export interface SessionUpdateOkPayload {
    applied: boolean;
}

export interface SessionDeletePayload {
    session: SessionId;
}

export interface SessionDeleteOkPayload {
    deleted: boolean;
}

export interface SessionCatalog {
    session_head: { req: SessionHeadPayload; ok: SessionHeadOkPayload };
    events_after: { req: EventsAfterPayload; ok: EventsAfterOkPayload };
    append: { req: AppendPayload; ok: AppendOkPayload };
    session_create: { req: SessionCreatePayload; ok: SessionCreateOkPayload };
    session_list: { req: SessionListPayload; ok: SessionListOkPayload };
    session_update: { req: SessionUpdatePayload; ok: SessionUpdateOkPayload };
    session_delete: { req: SessionDeletePayload; ok: SessionDeleteOkPayload };
}

export const SESSION_REPLIES = {
    session_head: "session_head_ok",
    events_after: "events_after_ok",
    append: "append_ok",
    session_create: "session_create_ok",
    session_list: "session_list_ok",
    session_update: "session_update_ok",
    session_delete: "session_delete_ok",
} as const satisfies Record<keyof SessionCatalog, string>;
