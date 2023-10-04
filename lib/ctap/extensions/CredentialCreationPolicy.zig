const std = @import("std");
/// Protection level for credentials
///
/// Authenticators supporting some form of user verification MUST process this extension
/// and persist the credProtect value with the credential, even if the authenticator is
/// not protected by some form of user verification at the time.
///
/// Authenticators may choose a higher policy than requested.
pub const CredentialCreationPolicy = enum(u8) {
    /// This reflects "FIDO_2_0" semantics. In this configuration, performing some
    /// form of user verification is OPTIONAL with or without credentialID list.
    /// This is the default state of the credential if the extension is not specified.
    userVerificationOptional = 0x01,
    /// In this configuration, credential is discovered only when its credentialID
    /// is provided by the platform or when some form of user verification is performed.
    userVerificationOptionalWithCredentialIDList = 0x02,
    /// This reflects that discovery and usage of the credential MUST be preceded
    /// by some form of user verification.
    userVerificationRequired = 0x03,

    pub fn toString(self: @This()) []const u8 {
        return switch (self) {
            .userVerificationOptional => "userVerificationOptional",
            .userVerificationOptionalWithCredentialIDList => "userVerificationOptionalWithCredentialIDList",
            .userVerificationRequired => "userVerificationRequired",
        };
    }

    pub fn fromString(s: []const u8) ?@This() {
        if (std.mem.eql(u8, s, "userVerificationOptional")) {
            return @This().userVerificationOptional;
        } else if (std.mem.eql(u8, s, "userVerificationOptionalWithCredentialIDList")) {
            return @This().userVerificationOptionalWithCredentialIDList;
        } else if (std.mem.eql(u8, s, "userVerificationRequired")) {
            return @This().userVerificationRequired;
        } else {
            return null;
        }
    }
};
