/** Chain hash of the agent event log: sha256 hex over `prevHash ‖ canon(event)`. */

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

export interface HashableEvent {
    seq: number;
    type: string;
    payload: unknown;
}

// genesis: the first event of a session chains onto the empty string
export const GENESIS_HASH = "";

const encoder = new TextEncoder();
// Event payloads are shallow in practice; this bounds hostile nesting before it consumes unbounded work.
const MAX_CANON_DEPTH = 100;

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function ownDataValue(object: object, key: string): unknown {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
        throw new TypeError(`Canonical JSON requires an own enumerable data property named ${key}`);
    }
    return descriptor.value;
}

function normalizeJson(value: unknown, depth: number, ancestors: Set<object>): JsonValue {
    if (value === null || typeof value === "string" || typeof value === "boolean") return value;
    if (typeof value === "number") {
        if (!Number.isFinite(value)) throw new TypeError("Canonical JSON requires finite numbers");
        return value;
    }
    if (typeof value !== "object") throw new TypeError(`Canonical JSON cannot encode ${typeof value}`);
    if (depth > MAX_CANON_DEPTH) throw new RangeError(`Canonical JSON exceeds maximum depth of ${MAX_CANON_DEPTH}`);
    if (ancestors.has(value)) throw new TypeError("Canonical JSON cannot encode cyclic values");

    ancestors.add(value);
    try {
        if (Array.isArray(value)) {
            const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
            const keys: string[] = [];
            for (const key of Reflect.ownKeys(value)) {
                if (key === "length") continue;
                if (typeof key !== "string") throw new TypeError("Canonical JSON cannot encode symbol keys");
                const descriptor = Object.getOwnPropertyDescriptor(value, key);
                if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
                    throw new TypeError("Canonical JSON requires an enumerable data property");
                }
                keys.push(key);
            }
            const length = lengthDescriptor !== undefined && "value" in lengthDescriptor ? lengthDescriptor.value as number : -1;
            if (keys.length !== length || keys.some((key, index) => key !== String(index))) {
                throw new TypeError("Canonical JSON requires dense arrays without extra properties");
            }
            const normalized: JsonValue[] = [];
            for (const key of keys) {
                normalized.push(normalizeJson(ownDataValue(value, key), depth + 1, ancestors));
            }
            return normalized;
        }

        const prototype = Object.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null) throw new TypeError("Canonical JSON requires plain objects");
        const sorted = Object.create(null) as Record<string, JsonValue>;
        const keys = Reflect.ownKeys(value);
        if (keys.some((key) => typeof key !== "string")) throw new TypeError("Canonical JSON cannot encode symbol keys");
        for (const key of (keys as string[]).sort()) {
            sorted[key] = normalizeJson(ownDataValue(value, key), depth + 1, ancestors);
        }
        return sorted;
    } finally {
        ancestors.delete(value);
    }
}

export function canon(event: HashableEvent): string {
    if (event === null || typeof event !== "object") throw new TypeError("Canonical JSON requires an event object");
    const selected = {
        seq: ownDataValue(event, "seq"),
        type: ownDataValue(event, "type"),
        payload: ownDataValue(event, "payload"),
    };
    return JSON.stringify(normalizeJson(selected, 0, new Set()));
}

export function chainHash(prevHash: string, event: HashableEvent): string {
    return bytesToHex(sha256(encoder.encode(prevHash + canon(event))));
}
