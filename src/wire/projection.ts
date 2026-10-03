// The stored log → the Message[] a prompt is built from: compaction replaces, truncate hides, parity repaired.

import type { Message, ToolCall } from "../types.ts";
import type { StoredEvent } from "./session.ts";

// `seq` is where the message sits in the log; `span` is the largest raw seq it stands for (a summary stands for its compaction event).
export interface FoldedEntry {
    seq: number;
    span: number;
    message: Message;
}

type Range = [number, number];

export const INTERRUPTED_TOOL_RESULT = "[interrupted — the tool never returned a result]";

// Safety-critical: a stored payload may carry more (`thinking`, display-only `meta`), and anything surviving here reaches a provider body.
const IMAGE_DATA_URI = /^data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/]+={0,2}$/;

/** Only inline raster images: a remote URL would be fetched by the model host (SSRF) or the owner's device (a beacon). */
export const isImageDataUri = (s: string): boolean => IMAGE_DATA_URI.test(s);

export function projectMessage(p: unknown): Message | null {
    if (p === null || typeof p !== "object" || Array.isArray(p)) return null;
    const m = p as Record<string, unknown>;
    const role = m["role"];
    if (role !== "system" && role !== "user" && role !== "assistant" && role !== "tool") return null;
    const toolCalls: ToolCall[] = [];
    if (role === "assistant" && Array.isArray(m["tool_calls"])) {
        const ids = new Set<string>();
        for (const raw of m["tool_calls"]) {
            if (raw === null || typeof raw !== "object" || Array.isArray(raw)) continue;
            const call = raw as Record<string, unknown>;
            if (
                typeof call["id"] === "string" &&
                typeof call["name"] === "string" &&
                typeof call["arguments"] === "string" &&
                !ids.has(call["id"])
            ) {
                ids.add(call["id"]);
                toolCalls.push({ id: call["id"], name: call["name"], arguments: call["arguments"] });
            }
        }
    }
    const images = Array.isArray(m["images"])
        ? m["images"].filter((x): x is string => typeof x === "string" && isImageDataUri(x))
        : [];
    return {
        role,
        content: typeof m["content"] === "string" ? m["content"] : null,
        ...(toolCalls.length ? { tool_calls: toolCalls } : {}),
        ...(images.length ? { images } : {}),
        ...(role === "tool" && typeof m["tool_call_id"] === "string" ? { tool_call_id: m["tool_call_id"] } : {}),
    };
}

// Providers reject a `tool_calls` message with missing results: each `tool` reply pairs with the immediately-preceding open group (else dropped), unanswered calls get a synthetic result.
export function sanitizeHistory(messages: readonly Message[]): Message[] {
    const out: Message[] = [];
    let unanswered: Set<string> | null = null;

    const closeGroup = (): void => {
        if (!unanswered) return;
        for (const id of unanswered) out.push({ role: "tool", tool_call_id: id, content: INTERRUPTED_TOOL_RESULT });
        unanswered = null;
    };

    for (const m of messages) {
        if (m.role === "tool") {
            if (m.tool_call_id && unanswered?.delete(m.tool_call_id)) {
                out.push(m);
            }
            continue;
        }
        closeGroup();
        if (m.role === "assistant" && m.tool_calls?.length) unanswered = new Set(m.tool_calls.map((c) => c.id));
        out.push(m);
    }
    closeGroup();
    return out;
}

const mergedRanges = (source: readonly Range[]): Range[] => {
    const sorted = source.filter(([from, to]) => from <= to).sort((a, b) => a[0] - b[0]);
    const ranges: Range[] = [];
    for (const [from, to] of sorted) {
        const previous = ranges.at(-1);
        if (previous && from <= previous[1]) previous[1] = Math.max(previous[1], to);
        else ranges.push([from, to]);
    }
    return ranges;
};

const rangeContains = (ranges: readonly Range[], seq: number): boolean => {
    let low = 0;
    let high = ranges.length - 1;
    while (low <= high) {
        const mid = (low + high) >>> 1;
        const [from, to] = ranges[mid]!;
        if (seq < from) high = mid - 1;
        else if (seq > to) low = mid + 1;
        else return true;
    }
    return false;
};

/** A well-formed truncate event hides seqs from `from` up to, not including, its own seq `at`. */
export function truncateCut(ev: StoredEvent): { from: number; at: number } | null {
    if (ev.type !== "truncate") return null;
    const from = (ev.payload as { fromSeq?: unknown } | null | undefined)?.fromSeq;
    return typeof from === "number" && Number.isFinite(from) ? { from, at: ev.seq } : null;
}

export function foldEvents(events: readonly StoredEvent[]): FoldedEntry[] {
    const hidden: Range[] = [];
    const compacted: Range[] = [];
    // Safety-critical like `projectMessage`: cuts arrive unvalidated, so a malformed one is dropped here and both passes read the checked copy.
    const cuts: { seq: number; from: number; summary: string | null }[] = [];

    for (const ev of events) {
        if (ev.type === "compaction") {
            const payload = ev.payload as { summary?: unknown; covers?: unknown } | null | undefined;
            const summary = payload?.summary;
            const covers = payload?.covers;
            if (typeof summary !== "string" || !Array.isArray(covers)) continue;
            const [from, to] = covers as unknown[];
            if (typeof from !== "number" || !Number.isFinite(from)) continue;
            if (typeof to !== "number" || !Number.isFinite(to)) continue;
            const end = Math.min(to, ev.seq - 1);
            cuts.push({ seq: ev.seq, from, summary });
            hidden.push([from, end]);
            compacted.push([from, end]);
        } else {
            const cut = truncateCut(ev);
            if (!cut) continue;
            cuts.push({ seq: cut.at, from: cut.from, summary: null });
            hidden.push([cut.from, cut.at - 1]);
        }
    }

    const compactedRanges = mergedRanges(compacted);
    const seenAnchors = new Set<number>();
    const summaries: FoldedEntry[] = [];
    let truncateFrom = Number.POSITIVE_INFINITY;
    for (let i = cuts.length - 1; i >= 0; i--) {
        const cut = cuts[i]!;
        if (cut.summary === null) {
            truncateFrom = Math.min(truncateFrom, cut.from);
        } else if (!seenAnchors.has(cut.from)) {
            // A later write at the same anchor replaces this summary even if that later summary is itself removed.
            seenAnchors.add(cut.from);
            // In a seq-ordered log every compacted range ends before its writer, so only a later range can contain this span.
            if (cut.from < truncateFrom && !rangeContains(compactedRanges, cut.seq)) {
                // The summary takes the place of its covered range, not the compaction event that wrote it.
                summaries.push({
                    seq: cut.from,
                    span: cut.seq,
                    message: { role: "assistant", content: cut.summary },
                });
            }
        }
    }

    const ranges = mergedRanges(hidden);
    const anchors = summaries.sort((a, b) => a.seq - b.seq);
    const out: FoldedEntry[] = [];
    let next = 0;
    for (const ev of events) {
        while (next < anchors.length && anchors[next]!.seq <= ev.seq) out.push(anchors[next++]!);
        const m = ev.type === "message" && !rangeContains(ranges, ev.seq) ? projectMessage(ev.payload) : null;
        if (m) out.push({ seq: ev.seq, span: ev.seq, message: m });
    }
    out.push(...anchors.slice(next));
    return out;
}
