export type Role = "system" | "user" | "assistant" | "tool";

export type ActorKind = "human" | "agent" | "system";

/** The human-visible author. `role` is the model's view and never establishes it; `agent` is the
 *  agent name when `kind` is "agent". Absent on events an agent appends itself — never guessed from text or time. */
export interface MessageActor {
    kind: ActorKind;
    agent?: string;
}

/** Display/provenance metadata written at append time. Inside the payload on purpose: it is part
 *  of the hashed event content. Stripped from every model-facing projection. */
export interface MessageMeta {
    callId?: string;
    registryModel?: string;
    actor?: MessageActor;
}

export interface Message {
    role: Role;
    content: string | null;
    /** Data-URIs (`data:image/png;base64,…`), model-facing only: they reach a vision model verbatim. */
    images?: string[];
    tool_calls?: ToolCall[];
    tool_call_id?: string;
    meta?: MessageMeta;
}

/** Provider-facing function shape; an agent's own declaration is `ToolSchema` in wire/handshake.ts. */
export interface Tool {
    type: "function";
    function: {
        name: string;
        description?: string;
        parameters?: Record<string, unknown>;
    };
}

export interface ToolCall {
    id: string;
    name: string;
    arguments: string;
}

export interface Usage {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
    cachedTokens: number;
    /** Provider-reported thinking tokens: a SUBSET of completionTokens, never added to any total.
     *  Absent means the provider reported none; an explicit 0 is a real report. */
    reasoningTokens?: number;
}

export const FINISH_REASONS = [
    "stop",
    "length",
    "tool_calls",
    "content_filter",
    "error",
    "aborted",
] as const;

export type FinishReason = (typeof FINISH_REASONS)[number];

export interface CompletionInfo {
    finishReason: FinishReason;
    usage?: Usage;
    meta?: unknown;
}

export type StreamEvent =
    | { type: "thinking"; text: string }
    | { type: "text"; text: string }
    | { type: "tool_calls"; calls: ToolCall[] }
    | ({ type: "done" } & CompletionInfo);
