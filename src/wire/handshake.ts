import type { Empty } from "./envelope/types.ts";

// the channel has already refused any PROTOCOL_VERSION mismatch, and a hello_ok means the pin is approved
export interface HelloPayload {
    agent: string;
}

export type HelloOkPayload = Empty;

/** ToolSchema.writes is the approval gate's input; distinct from the provider-facing Tool in types.ts. */
export interface ToolSchema {
    name: string;
    description?: string | undefined;
    parameters?: Record<string, unknown> | undefined;
    writes: boolean;
    /** The gateway folds this tool's call/result out of the visible transcript. */
    fold?: boolean;
}

export interface PromptPart {
    name: string;
    text: string;
}

export interface AgentPolicy {
    allowedTools?: string[];
    budgets?: Record<string, number>;
}

/** Commands this agent exposes to a2a callers — every entry must name a mounted tool (checked at boot). */
export interface AgentA2a {
    commands: string[];
}

export interface AgentManifest {
    name: string;
    /** One line of what the agent does, valid per isAgentDescription(); a gateway orchestrator routes by it. */
    description?: string;
    chain: boolean;
    model?: string;
    policy?: AgentPolicy;
    a2a?: AgentA2a;
}

export interface AgentAppPage {
    id: string;
    title: string;
    /** Absolute path inside the app; absent = the app's entry. */
    path?: string;
}

/** The gateway carries requests to this agent-hosted HTTP server over the agent's own channel, one stream per request. */
export interface AgentApp {
    title: string;
    entry?: string;
    pages?: AgentAppPage[];
    upstream: string;
}

/** A pack the agent left unmounted because these env keys are unset. */
export interface PackDisabled {
    name: string;
    missing: string[];
}

export type AvatarType = "image/png" | "image/webp" | "image/jpeg";

/** The agent's picture, at most AVATAR_MAX_BYTES raw; a receiver re-sniffs and re-hashes `data` rather than trust `type` or `sha256`. */
export interface AgentAvatar {
    type: AvatarType;
    /** Lowercase hex SHA-256 of the decoded bytes. */
    sha256: string;
    /** The raw image bytes, standard base64. */
    data: string;
}

export interface DescribePayload {
    manifest: AgentManifest;
    prompt: PromptPart[];
    tools: ToolSchema[];
    app?: AgentApp | undefined;
    packsDisabled?: PackDisabled[] | undefined;
    /** Absent: the agent has no avatar. */
    avatar?: AgentAvatar | undefined;
}

export interface ModelGrant {
    id: string;
    contextTokens?: number;
}

export interface DescribeOkPayload {
    models: ModelGrant[];
}

export interface HandshakeCatalog {
    hello: { req: HelloPayload; ok: HelloOkPayload };
    describe: { req: DescribePayload; ok: DescribeOkPayload };
}

export const HANDSHAKE_REPLIES = {
    hello: "hello_ok",
    describe: "describe_ok",
} as const satisfies Record<keyof HandshakeCatalog, string>;
