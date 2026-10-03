// ask_owner: the questions an agent's model puts to the owner through the gateway, and the owner's picks.

export const QUESTIONS_MAX = 4;
export const QUESTION_TEXT_MAX = 500;
export const QUESTION_OPTIONS_MIN = 2;
export const QUESTION_OPTIONS_MAX = 8;
export const QUESTION_LABEL_MAX = 80;
export const QUESTION_DESCRIPTION_MAX = 300;
export const QUESTION_OTHER_MAX = 2000;

export interface OwnerOption {
    /** One line, unique within its question (case-insensitive); the answer names the option by it. */
    label: string;
    description?: string | undefined;
}

export interface OwnerQuestion {
    question: string;
    options: OwnerOption[];
    /** More than one option may be picked. */
    multi?: boolean | undefined;
    /** The owner may answer in their own words, beside a pick or instead of one. */
    other?: boolean | undefined;
}

/** One question's answer: the picked labels in the options' order, and the owner's own words if any. */
export interface OwnerAnswer {
    selected: string[];
    other?: string | undefined;
}

/** What a device posts to answer a question gate: one answer per question, in order, or the dismissal. */
export type QuestionReply = { answers: OwnerAnswer[] } | { dismiss: true };

export type QuestionOutcome = "answered" | "dismissed" | "expired" | "gone";

/** The turn stream's events for a question gate, beside approval_required and approval_resolved. */
export interface QuestionRequiredEvent {
    type: "question_required";
    gate: string;
    questions: OwnerQuestion[];
    /** Epoch ms. */
    deadline: number;
}

export interface QuestionResolvedEvent {
    type: "question_resolved";
    gate: string;
    outcome: QuestionOutcome;
    /** null unless answered. */
    answers: OwnerAnswer[] | null;
}
