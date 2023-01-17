const cbor = @import("zbor");

pub const ErrorCodes = error{
    /// The command is not a valid CTAP command.
    invalid_command,
    /// Invalid message or item length.
    invalid_length,
    /// Error when parsing CBOR
    invalid_cbor,
};

pub const Errors = ErrorCodes || cbor.StringifyError;
