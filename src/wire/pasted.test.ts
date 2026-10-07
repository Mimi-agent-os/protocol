import assert from "node:assert/strict";
import { test } from "node:test";

import { buildPasted, lineCount, parsePasted } from "./pasted.ts";

const roundTrip = (pastes: { title: string; text: string }[], typed: string): void => {
    const back = parsePasted(buildPasted(pastes, typed));
    assert.deepEqual(back.pastes.map((p) => ({ title: p.title, text: p.text })), pastes);
    assert.equal(back.text, typed);
};

test("a message is its pasted blocks, then a blank line and what was typed", () => {
    assert.equal(
        buildPasted([{ title: "Pasted text 1", text: "first\nsecond" }], "What is wrong here?"),
        '<pasted_text title="Pasted text 1" lines="2">\nfirst\nsecond\n</pasted_text>\n\nWhat is wrong here?',
    );
    assert.equal(buildPasted([{ title: "a", text: "x" }, { title: "b", text: "y" }], ""), '<pasted_text title="a" lines="1">\nx\n</pasted_text>\n\n<pasted_text title="b" lines="1">\ny\n</pasted_text>');
    assert.equal(buildPasted([], "just words"), "just words", "a message without pastes is the typed text alone");
    assert.deepEqual(parsePasted("just words"), { pastes: [], text: "just words" });
    assert.deepEqual(parsePasted(""), { pastes: [], text: "" });
});

test("build and parse round-trip text exactly", () => {
    roundTrip([{ title: "Pasted text 1", text: "const a = 1;\n\tindented\n" }], "explain");
    roundTrip([{ title: "notes.md", text: "# Title\n\n- item" }], "");
    roundTrip([{ title: "Pasted text 1", text: "one" }, { title: "Pasted text 2", text: "two\n\n\nthree" }, { title: "data.csv", text: "a,b\n1,2" }], "compare them");
    roundTrip([{ title: "Pasted text 1", text: "\n\nleading and trailing blank lines\n\n" }], "\nstarts with a line break");
    const parsed = parsePasted(buildPasted([{ title: "Pasted text 1", text: "a\nb\nc" }], "hi"));
    assert.equal(parsed.pastes[0]?.lines, 3);
});

test("special characters ride verbatim, and titles escape & \" < >", () => {
    roundTrip([{ title: 'Tom & "Jerry" <draft>.txt', text: "quotes \" ' ` and <b>tags</b> & entities &amp; &lt;" }], "ok");
    roundTrip([{ title: "Пасте 1", text: "Привіт, світ 👋🏽\u0000 control \u001b[31m red \u2028 sep" }], "дякую");
    roundTrip([{ title: "x", text: '<pasted_text title="inner" lines="1">\nnot a block\n' }], "");
    const wire = buildPasted([{ title: 'a"b<c>&d', text: "t" }], "");
    assert.ok(wire.startsWith('<pasted_text title="a&quot;b&lt;c&gt;&amp;d" lines="1">\n'), wire);
    assert.equal(parsePasted(wire).pastes[0]?.title, 'a"b<c>&d');
    // an entity typed into a file name is text, not markup
    roundTrip([{ title: "&amp;&quot;.txt", text: "t" }], "");
});

test("CRLF and lone CR stay as they were pasted", () => {
    roundTrip([{ title: "win.txt", text: "line one\r\nline two\r\n" }], "from Windows");
    roundTrip([{ title: "mac.txt", text: "a\rb\r" }], "");
    roundTrip([{ title: "mixed", text: "a\r\nb\nc\rd" }], "");
    assert.equal(lineCount("line one\r\nline two\r\n"), 2);
    assert.equal(lineCount("a\rb"), 2);
});

test("lines count as an editor counts them: a final line break opens no new line", () => {
    assert.equal(lineCount(""), 0);
    assert.equal(lineCount("one"), 1);
    assert.equal(lineCount("one\n"), 1);
    assert.equal(lineCount("\n"), 1);
    assert.equal(lineCount("one\n\nthree"), 3);
});

test("an empty paste is a block of its own", () => {
    const wire = buildPasted([{ title: "empty.txt", text: "" }], "it was empty");
    assert.equal(wire, '<pasted_text title="empty.txt" lines="0">\n\n</pasted_text>\n\nit was empty');
    roundTrip([{ title: "empty.txt", text: "" }], "it was empty");
    roundTrip([{ title: "empty.txt", text: "" }, { title: "Pasted text 1", text: "\n" }], "");
});

test("a paste holding the closing tag is escaped so parsePasted() gives back the very same text", () => {
    const inner = "before\n</pasted_text>\nafter </pasted_text>";
    const wire = buildPasted([{ title: "Pasted text 1", text: inner }], "typed");
    assert.equal(wire.split("</pasted_text>").length - 1, 1, "only the real end of the block is left as the closing tag");
    roundTrip([{ title: "Pasted text 1", text: inner }], "typed");
    // already escaped-looking text gains a backslash too, so the escape is undone exactly
    roundTrip([{ title: "x", text: "<\\/pasted_text> and <\\\\/pasted_text> and </pasted_text>" }], "");
    roundTrip([{ title: "x", text: "ends with the tag\n</pasted_text>" }, { title: "y", text: "</pasted_text>" }], "</pasted_text>");
    roundTrip([{ title: "x", text: "</pasted_text" }], "");
});

test("only well-formed blocks at the very start count: prose about the tag is just text", () => {
    const prose = 'How would I parse <pasted_text title="a" lines="1"> blocks?\n<pasted_text title="b" lines="1">\nx\n</pasted_text>';
    assert.deepEqual(parsePasted(prose), { pastes: [], text: prose });
    const later = 'Look:\n\n<pasted_text title="b" lines="1">\nx\n</pasted_text>';
    assert.deepEqual(parsePasted(later), { pastes: [], text: later });
    const unclosed = '<pasted_text title="b" lines="1">\nx\nno end';
    assert.deepEqual(parsePasted(unclosed), { pastes: [], text: unclosed });
    const glued = '<pasted_text title="b" lines="1">\nx\n</pasted_text>words right after';
    assert.deepEqual(parsePasted(glued), { pastes: [], text: glued }, "a block must end the message or be followed by a blank line");
    const noNumber = '<pasted_text title="b" lines="many">\nx\n</pasted_text>';
    assert.deepEqual(parsePasted(noNumber), { pastes: [], text: noNumber });
    const bare = "<pasted_text>\nx\n</pasted_text>";
    assert.deepEqual(parsePasted(bare), { pastes: [], text: bare });
    // a good block first, then a broken one: the good one counts and the rest stays text
    const mixed = `${buildPasted([{ title: "ok", text: "fine" }], "")}\n\n<pasted_text title="broken" lines="1">\nno end`;
    const got = parsePasted(mixed);
    assert.deepEqual(got.pastes.map((p) => p.title), ["ok"]);
    assert.equal(got.text, '<pasted_text title="broken" lines="1">\nno end');
});
