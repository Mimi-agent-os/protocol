export {
    AGENT_DESCRIPTION_MAX,
    AGENT_NAME_SOURCE,
    AVATAR_MAX_BYTES,
    avatarType,
    CLOSE_NOT_PAIRED,
    GATEWAY_PORT,
    isAgentDescription,
    isAgentName,
    PROTOCOL_VERSION,
} from "./constants.ts";

export type {
    ActorKind,
    CompletionInfo,
    FinishReason,
    Message,
    MessageActor,
    MessageMeta,
    Role,
    StreamEvent,
    Tool,
    ToolCall,
    Usage,
} from "./types.ts";

export { GENESIS_HASH, chainHash } from "./crypto/hash.ts";
export type { HashableEvent } from "./crypto/hash.ts";
export { allPerms, fingerprint, noPerms, readPerms } from "./crypto/identity.ts";
export type { PinPerms, PinStatus } from "./crypto/identity.ts";

export { parseEnvelope } from "./wire/envelope/parse.ts";
export { NOTICE_TYPES, REPLY_OF } from "./wire/envelope/catalog.ts";
export type {
    Frame,
    FrameType,
    OkPayloadOf,
    RequestOf,
    RequestType,
    ReplyOf,
} from "./wire/envelope/catalog.ts";
export type { ProtocolError, Status, WireReply, WireRequest } from "./wire/envelope/types.ts";

export { A2A_PREFIX } from "./wire/a2a.ts";
export type { A2aCallOkPayload, A2aCallPayload, A2aInvokeOkPayload, A2aInvokePayload } from "./wire/a2a.ts";
export type {
    AgentApp,
    AgentAppPage,
    AgentAvatar,
    AgentManifest,
    AgentPolicy,
    AvatarType,
    DescribeOkPayload,
    DescribePayload,
    HelloOkPayload,
    HelloPayload,
    ModelGrant,
    PackDisabled,
    PromptPart,
    ToolSchema,
} from "./wire/handshake.ts";
export type {
    AppendOkPayload,
    AppendPayload,
    CompactionPayload,
    EventBody,
    EventsAfterOkPayload,
    EventsAfterPayload,
    SessionCreateOkPayload,
    SessionCreatePayload,
    SessionDeleteOkPayload,
    SessionDeletePayload,
    SessionHead,
    SessionHeadOkPayload,
    SessionHeadPayload,
    SessionId,
    SessionListOkPayload,
    SessionListPayload,
    SessionSummary,
    SessionUpdateOkPayload,
    SessionUpdatePayload,
    StoredEvent,
} from "./wire/session.ts";
export type {
    AskApproveOkPayload,
    AskApprovePayload,
    ChatOkPayload,
    ChatPayload,
    InvokePayload,
    ResultPayload,
} from "./wire/work.ts";
export type {
    HealthOkPayload,
    NotifyPayload,
    NotifyTarget,
} from "./wire/misc.ts";
export {
    QUESTION_DESCRIPTION_MAX,
    QUESTION_LABEL_MAX,
    QUESTION_OPTIONS_MAX,
    QUESTION_OPTIONS_MIN,
    QUESTION_OTHER_MAX,
    QUESTION_TEXT_MAX,
    QUESTIONS_MAX,
} from "./wire/questions.ts";
export type {
    OwnerAnswer,
    OwnerOption,
    OwnerQuestion,
    QuestionOutcome,
    QuestionReply,
    QuestionRequiredEvent,
    QuestionResolvedEvent,
} from "./wire/questions.ts";

export { foldEvents, INTERRUPTED_TOOL_RESULT, isImageDataUri, projectMessage, sanitizeHistory, truncateCut } from "./wire/projection.ts";
export type { FoldedEntry } from "./wire/projection.ts";

export { gatewayId, INVITE_ID_SOURCE, makeInviteUri, newInvite, parseInviteUri } from "./channel/pairing-invite.ts";
export type { Invite } from "./channel/pairing-invite.ts";
export { PairingInitiator, PairingResponder } from "./channel/pairing.ts";
export type { InitiatorEvent, ResponderEvent } from "./channel/pairing.ts";
export {
    APP_CHUNK,
    APP_CREDIT,
    APP_DETAIL_MAX,
    APP_HEADER_COUNT,
    APP_HEADER_MAX,
    APP_HEAD_MS,
    APP_IDLE_MS,
    APP_MAX_STREAMS,
    APP_PATH_MAX,
    APP_STALL_MS,
    APP_WINDOW,
    DEVICE_CREDIT,
    DEVICE_WINDOW,
    decodeAppReply,
    decodeAppRequestHeader,
} from "./channel/app-stream.ts";
export type {
    AppErrorReply,
    AppHeadReply,
    AppRequestHeader,
    AppStreamError,
    AppStreamPort,
} from "./channel/app-stream.ts";
export { FLAG_DATA, FLAG_END, FLAG_RESET } from "./channel/stream.ts";
export type { ChannelStreamFrame } from "./channel/stream.ts";
export { ClientSession, ServerSession } from "./channel/session.ts";
export type { ClientEvent, ServerEvent, ServerInfo } from "./channel/session.ts";
