//! Data Object definitions

const attestation_object = @import("dobj/attestation_object.zig");
pub const Flags = attestation_object.Flags;
pub const AttestedCredentialData = attestation_object.AttestedCredentialData;
pub const AuthData = attestation_object.AuthData;
pub const Fmt = attestation_object.Fmt;
pub const AttestationObject = attestation_object.AttestationObject;
pub const AttStmt = attestation_object.AttStmt;

pub const AuthenticatorOptions = @import("dobj/AuthenticatorOptions.zig");

pub const RelyingParty = @import("dobj/RelyingParty.zig");

pub const User = @import("dobj/User.zig");

pub const PublicKeyCredentialDescriptor = @import("dobj/PublicKeyCredentialDescriptor.zig");

pub const Options = @import("dobj/Options.zig");

pub const StatusCodes = @import("dobj/status.zig").StatusCodes;

pub const Errors = @import("dobj/error.zig").Errors;
pub const ErrorCodes = @import("dobj/error.zig").ErrorCodes;

pub const Versions = @import("dobj/version.zig").Versions;

test "data test" {
    _ = attestation_object;
}
