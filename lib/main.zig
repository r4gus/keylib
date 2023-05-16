/// Used by multiple data types
pub const common = struct {
    /// Representation of a relying party
    pub const RelyingParty = @import("common/RelyingParty.zig");
    /// Representation of a user
    pub const User = @import("common/User.zig");
    /// This enumeration defines the valid credential types
    pub const PublicKeyCredentialType = @import("common/PublicKeyCredentialType.zig").PublicKeyCredentialType;
    pub const PublicKeyCredentialParameters = @import("common/PublicKeyCredentialParameters.zig");
    /// Identifies a specific public key credential
    pub const PublicKeyCredentialDescriptor = @import("common/PublicKeyCredentialDescriptor.zig");
    /// Definitions for various transports for communicating with clients
    pub const AuthenticatorTransports = @import("common/AuthenticatorTransports.zig").AuthenticatorTransports;
    /// Parameters to influence authenticator operation
    pub const AuthenticatorOptions = @import("common/AuthenticatorOptions.zig");
    /// WebAuthn Attestation Statement Format Identifiers
    pub const AttestationStatementFormatIdentifiers = @import("common/AttestationStatementFormatIdentifiers.zig").AttestationStatementFormatIdentifiers;
    /// Attested credential data is a byte-array added to the authenticator data when
    /// generating an attestation object
    pub const AttestedCredentialData = @import("common/AttestedCredentialData.zig");
    /// The authenticator data structure encodes contextual bindings made by the authenticator
    pub const AuthenticatorData = @import("common/AuthenticatorData.zig");
    pub const AttestationStatement = @import("common/AttestationStatement.zig").AttestationStatement;

    test "common tests" {
        _ = RelyingParty;
        _ = User;
        _ = PublicKeyCredentialType;
        _ = PublicKeyCredentialParameters;
        _ = PublicKeyCredentialDescriptor;
        _ = AuthenticatorTransports;
        _ = AuthenticatorOptions;
        _ = AttestationStatementFormatIdentifiers;
        _ = AttestedCredentialData;
        _ = AuthenticatorData;
        _ = AttestationStatement;
    }
};

pub const ctap = struct {
    pub const param = struct {
        pub const MakeCredential = @import("ctap/param/MakeCredential.zig");
    };

    pub const response = struct {
        pub const MakeCredential = @import("ctap/response/MakeCredential.zig");
    };

    test "ctap tests" {
        _ = param.MakeCredential; // client -> authenticator
        _ = response.MakeCredential; // authenticator -> client
    }
};

/// PIN/UV Auth Protocol
///
/// A specific PIN/UV auth protocol defines an implementation of two interfaces
/// to cryptographic services: one for the authenticator, and one for the platform.
pub const pinuv = struct {
    /// Used by multiple data types
    pub const common = struct {
        /// Result of calling authenticate(pinUvAuthToken, clientDataHash)
        pub const PinUvAuthParam = [32]u8;

        /// PIN protocol versions
        pub const PinProtocol = enum(u16) {
            /// Pin protocol version 1
            V1 = 1,
            /// Pin Protocol version 2 for FIPS certified authenticators
            V2 = 2,
        };
    };

    /// The authenticator interface
    pub const authenticator = struct {};

    /// The platform interface
    pub const platform = struct {};

    test "pinuv tests" {}
};

test "library tests" {
    _ = common;
    _ = pinuv;
    _ = ctap;
}
