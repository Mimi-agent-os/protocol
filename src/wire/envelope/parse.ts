import type { ProtocolError, WireReply, WireRequest } from "./types.ts";

/** Validate the shared wire envelope. Domain handlers remain responsible for payload validation. */
export function parseEnvelope(
    value: unknown,
): WireRequest<string, unknown> | WireReply<string, unknown> | null {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
    const frame = value as Record<string, unknown>;
    if (!Object.hasOwn(frame, "id") || !Object.hasOwn(frame, "type")) return null;
    const id = frame["id"];
    const type = frame["type"];
    if (typeof id !== "string" || !id || typeof type !== "string" || !type) return null;

    if (!Object.hasOwn(frame, "status")) {
        if (!Object.hasOwn(frame, "payload")) return null;
        const request: WireRequest<string, unknown> = { id, type, payload: frame["payload"] };
        if (!Object.hasOwn(frame, "deadline")) return request;
        const deadline = frame["deadline"];
        if (deadline === undefined) return request;
        if (typeof deadline !== "number" || !Number.isFinite(deadline) || deadline < 0) return null;
        request.deadline = deadline;
        return request;
    }

    const status = frame["status"];
    switch (status) {
        case "ok":
            if (!Object.hasOwn(frame, "payload")) return null;
            return { id, type, status, payload: frame["payload"] };
        case "error":
        case "denied":
        case "timeout":
            break;
        default:
            return null;
    }

    if (!Object.hasOwn(frame, "error")) return null;
    const rawError = frame["error"];
    if (rawError === null || typeof rawError !== "object" || Array.isArray(rawError)) return null;
    const error = rawError as Record<string, unknown>;
    if (!Object.hasOwn(error, "message")) return null;
    const message = error["message"];
    const code = Object.hasOwn(error, "code") ? error["code"] : undefined;
    if (typeof message !== "string") return null;
    if (code !== undefined && typeof code !== "string") return null;
    const parsed: ProtocolError = { message };
    if (code !== undefined) parsed.code = code;
    if (Object.hasOwn(error, "detail")) parsed.detail = error["detail"];
    return { id, type, status, error: parsed };
}
