/// CTAPHID commands
pub const Cmd = enum(u8) {
    /// Transaction that echoes the data back.
    ping = 0x01,
    /// Encapsulated CTAP1/U2F message.
    msg = 0x03,
    /// Place an exclusive lock for one channel
    lock = 0x04,
    /// Allocate a new CID or synchronize channel.
    init = 0x06,
    /// Request authenticator to provide some visual or audible identification
    wink = 0x08,
    /// Encapsulated CTAP CBOR encoded message.
    cbor = 0x10,
    /// Cancel any outstanding requests on the given CID.
    cancel = 0x11,
    /// The request is still being processed
    keepalive = 0x3b,
    /// Error response message (see `ErrorCodes`).
    err = 0x3f,
};

pub const CMD_LENGTH = @sizeOf(Cmd);
