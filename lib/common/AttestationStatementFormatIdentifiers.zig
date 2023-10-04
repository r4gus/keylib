/// WebAuthn Attestation Statement Format Identifiers
///
/// https://www.w3.org/TR/webauthn/#sctn-defined-attestation-formats
pub const AttestationStatementFormatIdentifiers = enum {
    /// The "packed" attestation statement format is a WebAuthn-optimized format for attestation. It uses a very compact but still extensible encoding method. This format is implementable by authenticators with limited resources (e.g., secure elements).
    @"packed",
    /// The TPM attestation statement format returns an attestation statement in the same format as the packed attestation statement format, although the rawData and signature fields are computed differently.
    tpm,
    /// Platform authenticators on versions "N", and later, may provide this proprietary "hardware attestation" statement.
    @"android-key",
    /// Android-based platform authenticators MAY produce an attestation statement based on the Android SafetyNet API.
    @"android-safetynet",
    /// Used with FIDO U2F authenticators
    @"fido-u2f",
    /// Used with Apple devices' platform authenticators
    apple,
    /// Used to replace any authenticator-provided attestation statement when a WebAuthn Relying Party indicates it does not wish to receive attestation information.
    none,
};
