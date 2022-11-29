/// The minimum length of a PIN in bytes.
pub const minimum_pin_length: usize = 4;
/// The maximum length of a PIN in bytes.
pub const maximum_pin_length: usize = 63;
/// The maximum number of consecutive incorrect PIN attempts.
pub const maximum_pin_attempts: usize = 8;

/// PIN protocol versions
pub const PinProtocol = enum(u8) {
    /// Version 1 (the only version for fido2)
    v1 = 1,
};

/// Sub commands for PIN protocol version 1
pub const SubCommand = enum(u8) {
    getRetries = 0x01,
    getKeyAgreement = 0x02,
    setPIN = 0x03,
    changePIN = 0x04,
    getPINToken = 0x05,
};

pub const ClientPinParam = struct {
    /// punProtocol: PIN protocol version chosen by the client. For
    /// this version of the spec, this SHALL be the number 1.
    @"1": PinProtocol,
    /// subCommand: The authenticator Client PIN sub command currently
    /// being requested.
    @"2": SubCommand,
    /// keyAgreement: Public key of platformKeyAgreementKey. The
    /// COSE_Key-encoded public key MUST contain the optional "alg"
    /// parameter and MUST NOT contain any other optional parameters.
    /// The "alg" parameter MUST contain a COSEAlgorithmIdentifier value.
    @"3": ?[32]u8,
    /// pinAuth: First 16 bytes of HMAC-SHA-256 of encrypted contents
    /// using sharedSecret. See Setting a new PIN, Changing existing
    /// PIN and Getting pinToken from the authenticator for more details.
    @"4": ?[16]u8,
    /// newPinEnc: Encrypted new PIN using sharedSecret. Encryption is
    /// done over UTF-8 representation of new PIN.
    @"5": ?[]const u8,
    /// pinHashEnc: Encrypted first 16 bytes of SHA-256 of PIN using
    /// sharedSecret.
    @"6": ?[16]u8,
};

pub const ClientPinResponse = struct {
    /// pinToken: Encrypted pinToken using sharedSecret to be used in
    /// subsequent authenticatorMakeCredential and
    /// authenticatorGetAssertion operations.
    @"2": ?[]const u8 = null,
    /// retries: Number of PIN attempts remaining before lockout. This
    /// is optionally used to show in UI when collecting the PIN in
    /// Setting a new PIN, Changing existing PIN and Getting pinToken
    /// from the authenticator flows.
    @"3": ?u8 = null,
};
