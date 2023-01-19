/// CTAPHID commands
pub const Cmd = enum(u8) {
    /// Transaction that echoes the data back.
    ping = 0x01,
    /// Encapsulated CTAP1/U2F message.
    msg = 0x03,
    /// Allocate a new CID or synchronize channel.
    init = 0x06,
    /// Encapsulated CTAP CBOR encoded message.
    cbor = 0x10,
    /// Cancel any outstanding requests on the given CID.
    cancel = 0x11,
    /// Error response message (see `ErrorCodes`).
    err = 0x3f,
};

pub const CMD_LENGTH = @sizeOf(Cmd);
