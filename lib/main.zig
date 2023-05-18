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
    /// Authenticator (CTAP) versions
    pub const AuthenticatorVersions = @import("common/AuthenticatorVersions.zig").AuthenticatorVersions;
    /// An authenticator’s supported certifications (FIPS, FIDO, ...)
    pub const Certifications = @import("common/Certifications.zig");
    /// Type of attestation issued (None, Slef, ...)
    pub const AttestationType = @import("common/AttestationType.zig").AttestationType;

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
        _ = AuthenticatorVersions;
        _ = Certifications;
        _ = AttestationType;
    }
};

/// Client to authenticator protocol
pub const ctap = struct {
    /// Request data structures
    pub const request = struct {
        /// authenticatorMakeCredential request data structure
        pub const MakeCredential = @import("ctap/request/MakeCredential.zig");
        /// authenticatorGetAssertion request data structure
        pub const GetAssertion = @import("ctap/request/GetAssertion.zig");
    };

    /// Response data structures
    pub const response = struct {
        /// authenticatorMakeCredential response data structure (attestation object)
        pub const MakeCredential = @import("ctap/response/MakeCredential.zig");
        /// authenticatorGetAssertion response data structure
        pub const GetAssertion = @import("ctap/response/GetAssertion.zig");
    };

    /// Algorithms and data types for crypto
    pub const crypto = struct {
        /// Diffie-Hellman key exchange
        pub const dh = struct {
            pub const ecdh = @import("ctap/crypto/ecdh.zig");
            /// Elliptic curve diffie-hellman using the P-256 curve
            ///
            /// This is used to exchange a shared secret between client and
            /// authenticator when using the pinUvAuth protocol versions 1 and 2.
            pub const EcdhP256 = ecdh.EcdhP256;
        };

        /// This is the hash (computed using SHA-256) of the JSON-compatible
        /// serialization of client data, as constructed by the client
        pub const ClientDataHash = [32]u8;
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

    /// Authenticator related data structures
    pub const authenticator = struct {
        /// Authenticator settings that represent its capabilities
        pub const Settings = @import("ctap/auth/Settings.zig");
        /// Authenticator options
        pub const Options = @import("ctap/auth/Options.zig");
        /// Representation of a credential created by an authenticator
        pub const Credential = @import("ctap/auth/Credential.zig");
        /// Callbacks provided by the platform using this library
        pub const Callbacks = @import("ctap/auth/Callbacks.zig");
        /// Authenticator response
        pub const Response = @import("ctap/auth/Response.zig").Response;
    };

    /// CTAP commands
    pub const commands = struct {
        /// CTAP command identifier
        pub const Commands = @import("ctap/commands/Commands.zig").Commands;
        /// Authenticator commands
        pub const authenticator = struct {
            pub const authenticatorGetInfo = @import("ctap/commands/authenticator/get_info.zig").authenticatorGetInfo;
        };
    };

    /// CTAP status codes
    pub const StatusCodes = @import("ctap/StatusCodes.zig").StatusCodes;

    test "ctap tests" {
        _ = request.MakeCredential; // client -> authenticator
        _ = request.GetAssertion;
        _ = response.MakeCredential; // authenticator -> client
        _ = response.GetAssertion;
        _ = crypto.dh.ecdh;
        _ = pinuv;
        _ = authenticator.Settings;
        _ = authenticator.Options;
        _ = authenticator.Credential;
        _ = authenticator.Callbacks;
    }
};

test "library tests" {
    _ = common;
    _ = ctap;
}
