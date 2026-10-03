import assert from "node:assert/strict";
import { test } from "node:test";

import type { Message } from "../types.ts";
import { INTERRUPTED_TOOL_RESULT, foldEvents, projectMessage, sanitizeHistory } from "./projection.ts";
import type { EventBody, StoredEvent } from "./session.ts";

const log = (...bodies: EventBody[]): StoredEvent[] =>
    bodies.map((b, i) => ({ ...b, seq: i + 1, hash: "", createdAt: 0 }) as StoredEvent);

const user = (content: string): EventBody => ({ type: "message", payload: { role: "user", content } });

const said = (entries: readonly { message: Message }[]): string[] =>
    entries.map((e) => `${e.message.role}:${e.message.content ?? ""}`);

test("a projected message is exactly the neutral contract — stored extras never survive", () => {
    const stored = { role: "assistant", content: "yo", thinking: "secret", meta: { callId: "k1" }, tool_call_id: "c1" };
    assert.deepEqual(projectMessage(stored), { role: "assistant", content: "yo" });
    assert.equal(projectMessage([]), null);
    assert.equal(projectMessage({ content: "no role" }), null);
    assert.equal(projectMessage({ role: "developer", content: "untrusted" }), null);
});

test("images pass through as a string array — non-strings dropped, empty omits the field", () => {
    assert.deepEqual(
        projectMessage({ role: "user", content: "what is this?", images: ["data:image/png;base64,AAA", "data:image/png;base64,BBB"] }),
        { role: "user", content: "what is this?", images: ["data:image/png;base64,AAA", "data:image/png;base64,BBB"] },
    );
    // only inline raster data-URIs survive: a remote URL (SSRF / beacon) or any other data type is dropped
    assert.deepEqual(
        projectMessage({ role: "user", content: "x", images: ["data:image/jpeg;base64,QUJD", 5, null, "https://evil.example/x.png", "data:text/html;base64,PGI+"] }),
        { role: "user", content: "x", images: ["data:image/jpeg;base64,QUJD"] },
    );
    assert.deepEqual(projectMessage({ role: "user", content: "x", images: [] }), { role: "user", content: "x" });
    assert.deepEqual(projectMessage({ role: "user", content: "x", images: "nope" }), { role: "user", content: "x" });
});

test("projection admits one well-formed call per id from an assistant group", () => {
    assert.deepEqual(
        projectMessage({
            role: "assistant",
            content: null,
            tool_calls: [
                null,
                { id: "bad", name: "missing arguments" },
                { id: "ok", name: "search", arguments: "{}", internal: true },
                { id: "ok", name: "different command", arguments: "{}" },
            ],
        }),
        { role: "assistant", content: null, tool_calls: [{ id: "ok", name: "search", arguments: "{}" }] },
    );
    const empty = projectMessage({ role: "assistant", tool_calls: [null] });
    assert.ok(empty);
    assert.deepEqual(sanitizeHistory([empty]), [{ role: "assistant", content: null }]);
});

test("projection keeps tool fields only where the provider permits them", () => {
    assert.deepEqual(
        projectMessage({
            role: "user",
            content: "hi",
            tool_calls: [{ id: "c1", name: "search", arguments: "{}" }],
            tool_call_id: "c1",
        }),
        { role: "user", content: "hi" },
    );
    assert.deepEqual(
        projectMessage({
            role: "tool",
            content: "result",
            tool_calls: [{ id: "c1", name: "search", arguments: "{}" }],
            tool_call_id: "c1",
        }),
        { role: "tool", content: "result", tool_call_id: "c1" },
    );
});

test("a call id may recur in a later assistant group", () => {
    const first = projectMessage({
        role: "assistant",
        content: null,
        tool_calls: [{ id: "c1", name: "first", arguments: "{}" }],
    });
    const second = projectMessage({
        role: "assistant",
        content: null,
        tool_calls: [{ id: "c1", name: "second", arguments: "{}" }],
    });
    assert.ok(first && second);
    assert.deepEqual(
        sanitizeHistory([
            first,
            { role: "tool", content: "one", tool_call_id: "c1" },
            second,
            { role: "tool", content: "two", tool_call_id: "c1" },
        ]),
        [first, { role: "tool", content: "one", tool_call_id: "c1" }, second, { role: "tool", content: "two", tool_call_id: "c1" }],
    );
});

test("compaction replaces its covered range in place; later events stay after the summary", () => {
    const events = log(user("one"), user("two"), user("three"), user("four"), {
        type: "compaction",
        payload: { summary: "1-2", covers: [1, 2] },
    });
    const folded = foldEvents(events);
    assert.deepEqual(said(folded), ["assistant:1-2", "user:three", "user:four"]);
    assert.deepEqual(folded.map((e) => [e.seq, e.span]), [[1, 5], [3, 3], [4, 4]]);
});

test("truncate hides what precedes it from fromSeq on and applies to summary anchors", () => {
    const cut = log(user("one"), user("two"), user("three"), { type: "truncate", payload: { fromSeq: 2 } }, user("after"));
    assert.deepEqual(said(foldEvents(cut)), ["user:one", "user:after"]);

    const summarized = log(user("one"), user("two"), { type: "compaction", payload: { summary: "1-2", covers: [1, 2] } }, {
        type: "truncate",
        payload: { fromSeq: 1 },
    });
    assert.deepEqual(foldEvents(summarized), []);

    const cutsAfterSummaryAnchor = log(user("one"), user("two"), {
        type: "compaction",
        payload: { summary: "1-2", covers: [1, 2] },
    }, {
        type: "truncate",
        payload: { fromSeq: 2 },
    });
    assert.deepEqual(said(foldEvents(cutsAfterSummaryAnchor)), ["assistant:1-2"]);
});

test("a malformed cut is skipped, never thrown on — the wire delivers these unvalidated", () => {
    const malformed = log(
        user("one"),
        { type: "compaction", payload: { summary: "no covers" } } as unknown as EventBody,
        { type: "compaction", payload: { summary: "covers is not a range", covers: 5 } } as unknown as EventBody,
        { type: "compaction", payload: { summary: 7, covers: [1, 1] } } as unknown as EventBody,
        { type: "compaction", payload: { summary: "not finite", covers: [1, Number.NaN] } } as unknown as EventBody,
        { type: "truncate", payload: null } as unknown as EventBody,
        { type: "truncate", payload: { fromSeq: "1" } } as unknown as EventBody,
        user("two"),
    );
    assert.deepEqual(said(foldEvents(malformed)), ["user:one", "user:two"]);

    const alongside = log(
        user("one"),
        { type: "compaction", payload: { summary: "x", covers: [Number.POSITIVE_INFINITY, 1] } } as unknown as EventBody,
        user("two"),
        { type: "truncate", payload: { fromSeq: 1 } },
        user("three"),
    );
    assert.deepEqual(said(foldEvents(alongside)), ["user:three"]);
});

test("a compaction that covers an earlier compaction event replaces its summary", () => {
    const nested = log(user("one"), user("two"), {
        type: "compaction",
        payload: { summary: "1-2", covers: [1, 2] },
    }, {
        type: "compaction",
        payload: { summary: "nested", covers: [2, 3] },
    });
    assert.deepEqual(said(foldEvents(nested)), ["assistant:nested"]);
});

test("a later summary at the same anchor replaces the earlier one", () => {
    const events = log(user("one"), user("two"), {
        type: "compaction", payload: { summary: "first", covers: [1, 2] },
    }, {
        type: "compaction", payload: { summary: "second", covers: [1, 2] },
    });
    assert.deepEqual(said(foldEvents(events)), ["assistant:second"]);
});

test("removing a replacement does not resurrect an older same-anchor summary", () => {
    const events = log(user("one"), user("two"), {
        type: "compaction", payload: { summary: "first", covers: [1, 2] },
    }, {
        type: "compaction", payload: { summary: "second", covers: [1, 2] },
    }, {
        type: "compaction", payload: { summary: "third", covers: [4, 4] },
    });
    assert.deepEqual(said(foldEvents(events)), ["assistant:third"]);
});

test("only truncates written after a summary remove its anchor", () => {
    const truncateFirst = log(user("one"), user("two"), {
        type: "truncate", payload: { fromSeq: 1 },
    }, {
        type: "compaction", payload: { summary: "later", covers: [1, 2] },
    });
    assert.deepEqual(said(foldEvents(truncateFirst)), ["assistant:later"]);

    const truncateLast = log(user("one"), user("two"), {
        type: "compaction", payload: { summary: "earlier", covers: [1, 2] },
    }, {
        type: "truncate", payload: { fromSeq: 1 },
    });
    assert.deepEqual(foldEvents(truncateLast), []);
});

test("separate covered ranges preserve the message between fractional boundaries", () => {
    const events = log(user("one"), user("two"), user("three"), {
        type: "compaction", payload: { summary: "first", covers: [0.5, 1.5] },
    }, {
        type: "compaction", payload: { summary: "third", covers: [2.5, 3.5] },
    });
    assert.deepEqual(said(foldEvents(events)), ["assistant:first", "user:two", "assistant:third"]);
});

test("many disjoint compactions preserve every replacement", () => {
    const count = 10_000;
    const events: StoredEvent[] = [];
    for (let seq = 1; seq <= count; seq++) {
        events.push({ ...user(`message ${seq}`), seq, hash: "", createdAt: 0 } as StoredEvent);
    }
    for (let anchor = 1; anchor <= count; anchor++) {
        events.push({
            type: "compaction",
            payload: { summary: `summary ${anchor}`, covers: [anchor, anchor] },
            seq: count + anchor,
            hash: "",
            createdAt: 0,
        });
    }

    const folded = foldEvents(events);
    assert.equal(folded.length, count);
    for (let index = 0; index < count; index++) {
        const anchor = index + 1;
        assert.deepEqual(
            folded[index],
            {
                seq: anchor,
                span: count + anchor,
                message: { role: "assistant", content: `summary ${anchor}` },
            },
            `replacement ${anchor}`,
        );
    }
});

test("sanitizeHistory drops orphan and duplicate tool results and backfills unanswered calls", () => {
    const history: Message[] = [
        { role: "user", content: "hi" },
        { role: "tool", content: "from nowhere", tool_call_id: "ghost" },
        { role: "assistant", content: null, tool_calls: [{ id: "a", name: "t", arguments: "{}" }, { id: "b", name: "t", arguments: "{}" }] },
        { role: "tool", content: "ok", tool_call_id: "a" },
        { role: "tool", content: "ok again", tool_call_id: "a" },
        { role: "user", content: "never mind" },
    ];
    assert.deepEqual(
        sanitizeHistory(history).map((m) => `${m.role}:${m.tool_call_id ?? ""}:${m.content ?? ""}`),
        ["user::hi", "assistant::", "tool:a:ok", `tool:b:${INTERRUPTED_TOOL_RESULT}`, "user::never mind"],
    );
});

test("sanitizeHistory backfills an open tool group at end of history", () => {
    const assistant: Message = {
        role: "assistant",
        content: null,
        tool_calls: [{ id: "a", name: "first", arguments: "{}" }, { id: "b", name: "second", arguments: "{}" }],
    };
    assert.deepEqual(sanitizeHistory([assistant]), [
        assistant,
        { role: "tool", tool_call_id: "a", content: INTERRUPTED_TOOL_RESULT },
        { role: "tool", tool_call_id: "b", content: INTERRUPTED_TOOL_RESULT },
    ]);
});

test("sanitizeHistory closes one assistant tool group before opening the next", () => {
    const first: Message = {
        role: "assistant",
        content: null,
        tool_calls: [{ id: "a", name: "first", arguments: "{}" }],
    };
    const second: Message = {
        role: "assistant",
        content: null,
        tool_calls: [{ id: "b", name: "second", arguments: "{}" }],
    };
    const result: Message = { role: "tool", content: "done", tool_call_id: "b" };
    assert.deepEqual(sanitizeHistory([first, second, result]), [
        first,
        { role: "tool", tool_call_id: "a", content: INTERRUPTED_TOOL_RESULT },
        second,
        result,
    ]);
});
