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
userId: []const u8,

/// Security policy for the credential
policy: fido.ctap.extensions.CredentialCreationPolicy,

/// Sign counter of the credential
signCtr: u32,

/// The key in CBOR-COSE format
key: cbor.cose.Key,

pub fn deinit(self: *const @This(), a: std.mem.Allocator) void {
    a.free(self.rpId);
    a.free(self.userId);
}
