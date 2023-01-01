const std = @import("std");
const cose = @import("zbor").cose;
const crypto = @import("crypto.zig");
const EcdhP256 = crypto.ecdh.EcdhP256;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// The minimum length of a PIN in bytes.
pub const minimum_pin_length: usize = 4;
/// The maximum length of a PIN in bytes.
pub const maximum_pin_length: usize = 63;
/// The maximum number of consecutive incorrect PIN attempts.
pub const maximum_pin_attempts: usize = 8;

/// PIN protocol versions
pub const PinProtocol = enum(u8) {
    /// Pin protocol version 1.
    v1 = 1,
    /// Pin Protocol version 2 for FIPS certified authenticators.
    /// Currently not supported!
    v2 = 2,
};

/// Sub commands for PIN protocol version 1
pub const SubCommand = enum(u8) {
    getRetries = 0x01,
    getKeyAgreement = 0x02,
    setPIN = 0x03,
    changePIN = 0x04,
    getPINToken = 0x05,
    getPinUvAuthTokenUsingUv = 0x06,
    getUvRetries = 0x07,
    getPinUvAuthTokenUsingPin = 0x08,
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
    @"3": ?cose.Key,
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
    @"1": ?cose.Key = null,
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

pub const AuthProtocolState = struct {
    /// A ECDH key denoted by (a, aG) where "a" denotes
    /// the private key and "aG" denotes the public key. A new
    /// key is generated on each powerup.
    authenticator_key_agreement_key: EcdhP256.KeyPair,
    /// A random integer of length which is multiple of 16 bytes
    /// (AES block length).
    pin_token: [32]u8,
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

pub const PinUvAuthTokenPermissions = packed struct {
    mc: u1 = 0,
    ga: u1 = 0,
    cm: u1 = 0,
    be: u1 = 0,
    lbw: u1 = 0,
    acfg: u1 = 0,
};

pub const PinUvAuthTokenState = struct {
    /// A permissions RP ID, initially null
    rp_id: ?[]const u8 = null,
    permissions: PinUvAuthTokenPermissions = 0,
    // TODO: usage_timer
    in_use: bool = false,
    /// The platform MUST invoke an authenticator operation using the pinUvAuthToken within this time limit
    initial_usage_time_limit: u64 = 19000, // 19 s = 19000 ms
    /// The length of time the user is considered "present", as represented by the userPresent flag
    user_present_time_limit: u64 = 19000, // 19 s = 19000 ms
    max_usage_time_period: u64 = 600000, // 10 min = 600 s = 600000 ms
    user_verified: bool = false,
    user_present: bool = false,
    /// The time in ms `beginUsingPinUvAuthToken` was called. Reference point to check
    /// if a time limit has been reached.
    usage_timer: ?u64 = null,
    /// Token has been used at least once
    used: bool = false,
    pinRetries: u8,
    uvRetries: u8,
    /// The PIN/UV auth protocol state
    state: ?AuthProtocolState = null,

    /// This function prepares the pinUvAuthToken for use by the platform, which has
    /// invoked one of the pinUvAuthToken-issuing operations, by setting particular
    /// pinUvAuthToken state variables to given use-case-specific values.
    pub fn beginUsingPinUvAuthToken(self: *@This(), user_is_present: bool, start: u64) void {
        self.user_present = user_is_present;
        self.user_verified = true;
        self.initial_usage_time_limit = 19000; // 19 s = 19000 ms
        // Set the usage_timer to the current number of ms.
        // We wont use an observer but will instead always compare the
        // time_limit against usage_timer - millis().
        self.usage_timer = start;
        self.in_use = true;
    }

    /// Observes the pinUvAuthToken usage timer and takes appropriate action.
    pub fn pinUvAuthTokenUsageTimerObserver(self: *@This(), time_ms: u64) void {
        if (self.usage_timer == null) return;
        const delta = time_ms - self.usage_timer.?;

        if (delta > self.user_present_time_limit) {
            // current user present time limit is reached
            if (self.in_use) self.user_present = false;
        }

        // If the initial usage time limit is reached without the platform using the pinUvAuthToken
        // in an authenticator operation then call stopUsingPinUvAuthToken(), and terminate these steps.
        if ((delta > self.initial_usage_time_limit and !self.used) or delta > self.max_usage_time_period) {
            self.in_use = false;
            self.initial_usage_time_limit = 19000;
            self.user_present_time_limit = 19000;
            self.user_verified = false;
            self.user_present = false;
            self.usage_timer = null;
            self.used = false;
            return;
        }
    }

    /// If the pinUvAuthToken is in use then clear all of the pinUvAuthToken's
    /// permissions, except for lbw.
    pub fn clearPinUvAuthTokenPermissionsExceptLbw(self: *@This()) void {
        self.permissions &= 0x10;
    }

    pub fn stopUsingPinUvAuthToken(self: *@This()) void {
        self.rp_id = null;
        self.permissions = 0;
        self.is_use = false;
        self.initial_usage_time_limit = 19000;
        self.user_present_time_limit = 19000;
        self.max_usage_time_period = 600000;
        self.user_verified = false;
        self.user_present = false;
        self.usage_timer = null;
        self.used = false;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // PIN/UV Auth Protocol (one)
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    pub fn initialize(self: *@This(), rand: *const fn ([]u8) void) void {
        self.regenerate(rand);
        self.resetPinUvAuthToken(rand);
    }

    /// Generate a fresh, random P-256 private key, x.
    fn regenerate(self: *@This(), rand: *const fn ([]u8) void) void {
        var seed: [EcdhP256.secret_length]u8 = undefined;
        rand(seed[0..]);

        self.state = .{
            .authenticator_key_agreement_key = try EcdhP256.KeyPair.create(seed),
            .pin_token = undefined,
        };
    }

    /// Generate a fresh 32 bytes pinUvAuthToken.
    fn resetPinUvAuthToken(self: *@This(), rand: *const fn ([]u8) void) void {
        rand(self.state.?.pin_token[0..]);
    }

    /// Return the public part of the key as COSE key.
    pub fn getPublicKey(self: *const @This()) cose.Key {
        return cose.Key.fromP256Pub(
            .EcdhEsHkdf256,
            self.state.?.authenticator_key_agreement_key,
        );
    }

    pub fn ecdh(self: *const @This(), peer_cose_key: cose.Key) ![Sha256.digest_length]u8 {
        const shared_point = try EcdhP256.scalarmultXY(
            self.state.?.authenticator_key_agreement_key.secret_key,
            peer_cose_key.@"-2_b",
            peer_cose_key.@"-3_b",
        );
        // let z be the 32-byte, big-endian encoding of the x-coordinate
        // of the shared point
        const z: [32]u8 = shared_point.toUncompressedSec1()[1..33].*;
        var shared: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(z[0..], &shared, .{});
        return z;
    }

    // TODO: resume at encapsulate ( §6.5.6)
};
