//! Representation of a credential created by an authenticator and bound
//! to a specific relying party.

const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");

/// The id of the given credential
id: [64]u8,

/// The id (base URL) the credential is bound to
rpId: []const u8,

/// The account id the credential is created for
user: fido.common.User,

/// Security policy for the credential
policy: fido.ctap.extensions.CredentialCreationPolicy,

/// Sign counter of the credential
signCtr: u32,

/// The time the credential was created, e.g. epoch-time in ms
///
/// This should always be the same unit to allow sorting based
/// on the given value (required for resident keys).
time_stamp: u64,

/// Key material returned from SigAlg.create()
key: struct {
    /// Raw key material
    raw: []const u8,
    /// Algorithm
    alg: cbor.cose.Algorithm,
},

/// Used for hmac-secret extension
cred_random: ?struct {
    CredRandomWithUV: [32]u8,
    CredRandomWithoutUV: [32]u8,
} = null,

pub fn deinit(self: *const @This(), a: std.mem.Allocator) void {
    a.free(self.rpId);
    a.free(self.key.raw);
    self.user.deinit(a);
}
