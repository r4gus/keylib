const std = @import("std");
const crypto = @import("crypto.zig");
const EcdhP256 = crypto.ecdh.EcdhP256;

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
    @"3": ?crypto.PlatformKeyAgreementKey,
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

    pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
        if (self.@"5") |pin| {
            allocator.free(pin);
        }
    }
};

pub const ClientPinResponse = struct {
    /// Authenticator key agreement public key in COSE_Key format. This will
    /// be used to establish a sharedSecret between platform and the authenticator.
    @"1": ?crypto.PlatformKeyAgreementKey = null,
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

pub const PinConf = struct {
    /// A ECDH key denoted by (a, aG) where "a" denotes
    /// the private key and "aG" denotes the public key. A new
    /// key is generated on each powerup.
    authenticator_key_agreement_key: EcdhP256.KeyPair,
    /// A random integer of length which is multiple of 16 bytes
    /// (AES block length).
    pin_token: [32]u8,
};

/// Create a new pin configuration which consists of a random token and a
/// ECDH-ES P256 public key.
pub fn makeConfig(rand: *const fn ([]u8) void) !PinConf {
    var seed: [EcdhP256.secret_length]u8 = undefined;
    var token: [32]u8 = undefined;
    rand(seed[0..]);
    rand(token[0..]);

    return .{
        .authenticator_key_agreement_key = try EcdhP256.KeyPair.create(seed),
        .pin_token = token,
    };
}
