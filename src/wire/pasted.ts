// Pasted text inside a user message, the one place that writes the blocks and reads them back: every paste as
// <pasted_text title=".." lines="..">, its text verbatim on the lines between, </pasted_text>, then a blank line and what was typed.

export interface Paste {
    /** "Pasted text 2", or the name of the file it came from. */
    title: string;
    lines: number;
    text: string;
}

const CLOSE = "</pasted_text>";
// sticky: a block counts only where the message, or the block before it, leaves off
const OPEN = /<pasted_text title="([^"]*)" lines="\d+">\n/y;
const ATTR: Record<string, string> = { "&": "&amp;", '"': "&quot;", "<": "&lt;", ">": "&gt;" };
const UNATTR: Record<string, string> = { amp: "&", quot: '"', lt: "<", gt: ">" };

/** Lines as an editor counts them: a final line break opens no new line. */
export function lineCount(text: string): number {
    if (text === "") return 0;
    const breaks = text.match(/\r\n|\r|\n/g)?.length ?? 0;
    return /[\r\n]$/.test(text) ? breaks : breaks + 1;
}

/** The message as sent. A literal closing tag in a text gains one backslash after its "<" (and every escaped one another), which parsePasted() takes off. */
export function buildPasted(pastes: readonly Pick<Paste, "title" | "text">[], typed: string): string {
    const blocks = pastes.map((p) => {
        const title = p.title.replace(/[&"<>]/g, (c) => ATTR[c] ?? c);
        const body = p.text.replace(/<(\\*)\/pasted_text>/g, "<\\$1/pasted_text>");
        return `<pasted_text title="${title}" lines="${lineCount(p.text)}">\n${body}\n${CLOSE}`;
    });
    return [...blocks, typed].filter((part) => part !== "").join("\n\n");
}

/** The well-formed blocks a message starts with, and the text after them; a tag anywhere else, prose about it included, is just text. */
export function parsePasted(message: string): { pastes: Paste[]; text: string } {
    const pastes: Paste[] = [];
    let at = 0;
    for (;;) {
        OPEN.lastIndex = at;
        const head = OPEN.exec(message);
        if (!head) break;
        const start = OPEN.lastIndex;
        const end = message.indexOf(`\n${CLOSE}`, start);
        if (end < 0) break;
        const after = end + 1 + CLOSE.length;
        if (after < message.length && !message.startsWith("\n\n", after)) break;
        const text = message.slice(start, end).replace(/<\\(\\*)\/pasted_text>/g, "<$1/pasted_text>");
        pastes.push({ title: (head[1] ?? "").replace(/&(amp|quot|lt|gt);/g, (_, name: string) => UNATTR[name] ?? name), lines: lineCount(text), text });
        at = Math.min(after + 2, message.length);
    }
    return { pastes, text: message.slice(at) };
}
