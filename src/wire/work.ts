// Work both ways: the gateway invokes the agent's tools; the agent asks it for model calls. Approval is asked mid-invoke, not before.

import type { FinishReason, Message, StreamEvent, Tool, ToolCall, Usage } from "../types.ts";
import type { WireNotice } from "./envelope/types.ts";
import type { SessionId } from "./session.ts";

export interface InvokePayload {
    tool: string;
    args: Record<string, unknown>;
    session?: SessionId;
}

export interface ResultPayload {
    text: string;
    data?: unknown;
}

export interface AskApprovePayload {
    label: string;
    detail?: Record<string, unknown>;
    session?: SessionId;
}

export interface AskApproveOkPayload {
    approved: boolean;
    reason?: string;
}

export interface ChatPayload {
    messages: Message[];
    model?: string | undefined;
    tools?: Tool[];
    stream?: boolean;
    params?: Record<string, unknown>;
    scope?: string;
    session?: SessionId;
    /** Prepend the agent's own system prompt (persona, pack parts, date) the way a turn does. */
    withPrompt?: boolean;
}

export interface ChatOkPayload {
    text: string;
    thinking: string;
    toolCalls: ToolCall[];
    finishReason: FinishReason;
    usage?: Usage;
}

// carries the `id` of the `chat` it belongs to; the terminating reply is `chat_ok`
export type StreamFrame = WireNotice<"stream", StreamEvent>;

export interface WorkCatalog {
    invoke: { req: InvokePayload; ok: ResultPayload };
    ask_approve: { req: AskApprovePayload; ok: AskApproveOkPayload };
    chat: { req: ChatPayload; ok: ChatOkPayload };
}

export const WORK_REPLIES = {
    invoke: "result",
    ask_approve: "ask_approve_ok",
    chat: "chat_ok",
} as const satisfies Record<keyof WorkCatalog, string>;
