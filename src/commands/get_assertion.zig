const std = @import("std");
const cbor = @import("zbor");
const dobj = @import("../dobj.zig");
const PublicKeyCredentialDescriptor = @import("../public_key_credential_descriptor.zig").PublicKeyCredentialDescriptor;

pub const GetAssertionParam = struct {
    /// rpId: Relying party identifier.
    @"1": [:0]const u8,
    /// clientDataHash: Hash of the serialized client data collected by the host.
    @"2": []const u8,
    /// allowList: A sequence of PublicKeyCredentialDescriptor structures, each
    /// denoting a credential, as specified in [WebAuthN]. If this parameter is
    /// present and has 1 or more entries, the authenticator MUST only generate
    /// an assertion using one of the denoted credentials.
    @"3": ?[]const PublicKeyCredentialDescriptor = null,
    // TODO: add remaining fields (extensions 0x4)
    /// options: Parameters to influence authenticator operation.
    @"5": ?dobj.AuthenticatorOptions = null,
    /// pinAuth: First 16 bytes of HMAC-SHA-256 of clientDataHash using pinToken
    /// which platform got from the authenticator:
    /// HMAC-SHA-256(pinToken, clientDataHash).
    @"6": ?[16]u8 = null,
    /// pinProtocol: PIN protocol version selected by client.
    @"7": ?u8 = null,

    pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
        allocator.free(self.@"1");
        allocator.free(self.@"2");
        if (self.@"3") |pkcds| {
            for (pkcds) |pkcd| {
                pkcd.deinit(allocator);
            }
            allocator.free(pkcds);
        }
    }
};

pub const GetAssertionResponse = struct {
    /// credential: PublicKeyCredentialDescriptor structure containing the
    /// credential identifier whose private key was used to generate the
    /// assertion. May be omitted if the allowList has exactly one Credential.
    @"1": PublicKeyCredentialDescriptor,
    /// authData: The signed-over contextual bindings made by the authenticator,
    /// as specified in [WebAuthN].
    @"2": []const u8,
    /// signature: The assertion signature produced by the authenticator, as
    /// specified in [WebAuthN].
    @"3": []const u8,
    // @"4": TODO: add user (0x4)
    /// numberOfCredentials: Total number of account credentials for the RP.
    /// This member is required when more than one account for the RP and the
    /// authenticator does not have a display. Omitted when returned for the
    /// authenticatorGetNextAssertion method.
    @"5": ?u64 = null,
};
