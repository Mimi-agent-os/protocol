// A2A invokes a named command without an LLM turn on either side.

import type { ResultPayload } from "./work.ts";

export const A2A_PREFIX = "a2a_";

export interface A2aCallPayload {
    agent: string;
    command: string;
    args: Record<string, unknown>;
}

export interface A2aCallOkPayload {
    result: ResultPayload;
}

export interface A2aInvokePayload {
    from: string;
    command: string;
    args: Record<string, unknown>;
}

export interface A2aInvokeOkPayload {
    result: ResultPayload;
}

export interface A2aCatalog {
    a2a_call: { req: A2aCallPayload; ok: A2aCallOkPayload };
    a2a_invoke: { req: A2aInvokePayload; ok: A2aInvokeOkPayload };
}

export const A2A_REPLIES = {
    a2a_call: "a2a_call_ok",
    a2a_invoke: "a2a_invoke_ok",
} as const satisfies Record<keyof A2aCatalog, string>;
