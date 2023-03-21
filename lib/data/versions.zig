/// Supported version of the authenticator.
pub const Versions = enum {
    FIDO_2_1,
    FIDO_2_1_PRE,
    /// For CTAP2/FIDO2/Web Authentication authenticators.
    FIDO_2_0,
    /// For CTAP1/U2F authenticators.
    U2F_V2,
};
