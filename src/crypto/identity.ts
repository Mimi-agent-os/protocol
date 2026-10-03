/** Pinned-key identity: the fingerprints a person reads, and the permission shape a pin carries. */

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

export type PinStatus = "approved" | "blocked";

export interface PinPerms {
    delegate: boolean;
    discoverable: boolean;
}

export const noPerms = (): PinPerms => ({
    delegate: false,
    discoverable: false,
});

export const allPerms = (): PinPerms => ({ delegate: true, discoverable: true });

export function readPerms(raw: unknown): PinPerms {
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return noPerms();
    const delegate = Object.getOwnPropertyDescriptor(raw, "delegate");
    const discoverable = Object.getOwnPropertyDescriptor(raw, "discoverable");
    return {
        delegate: delegate?.enumerable === true && "value" in delegate && delegate.value === true,
        discoverable: discoverable?.enumerable === true && "value" in discoverable && discoverable.value === true,
    };
}

/** What a pin is stored and listed under: "sha256:aaaa-bbbb-…", 8 groups of the digest's first 128 bits. A wire key is base64. */
export function fingerprint(pubkey: Uint8Array | string): string {
    let bytes = pubkey;
    if (typeof bytes === "string") {
        const bin = atob(bytes);
        if (btoa(bin) !== bytes) throw new Error("non-canonical base64");
        bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    }
    const hex = bytesToHex(sha256(bytes));
    return `sha256:${hex.slice(0, 32).match(/.{4}/g)!.join("-")}`;
}
