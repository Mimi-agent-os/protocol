export type Status = "ok" | "error" | "denied" | "timeout";

export type Empty = Record<string, never>;

export interface ProtocolError {
    message: string;
    code?: string;
    detail?: unknown;
}

export interface WireRequest<T extends string, P> {
    id: string;
    type: T;
    payload: P;
    // budget in ms counted from receipt — never a wall clock, the two peers share no clock
    deadline?: number;
}

export interface WireNotice<T extends string, P> {
    id: string;
    type: T;
    payload: P;
}

export type WireReply<T extends string, P> =
    | { id: string; type: T; status: "ok"; payload: P }
    | {
          id: string;
          type: T;
          status: Exclude<Status, "ok">;
          error: ProtocolError;
      };
