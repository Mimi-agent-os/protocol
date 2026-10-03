import type { Empty, WireNotice } from "./envelope/types.ts";
import type { SessionId } from "./session.ts";

/** The gateway forwards `route` unchanged; only the target app interprets it. */
export interface NotifyTarget {
    kind: "chat" | "app";
    agent: string;
    session?: SessionId | undefined;
    route?: string | undefined;
}

/** Unprompted agent notices are stored in the gateway Inbox. */
export interface NotifyPayload {
    title: string;
    body?: string;
    level?: "info" | "warn" | "action";
    target?: NotifyTarget;
}

export type NotifyFrame = WireNotice<"notify", NotifyPayload>;

export interface HealthOkPayload {
    uptimeMs: number;
    sessions: number;
    lastError?: string | undefined;
}

export interface MiscCatalog {
    health: { req: Empty; ok: HealthOkPayload };
}

export const MISC_REPLIES = {
    health: "health_ok",
} as const satisfies Record<keyof MiscCatalog, string>;
