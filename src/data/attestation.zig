/// Type of attestation issued
pub const AttestationType = enum {
    /// In this case, no attestation information is available.
    None,
    /// In the case of self attestation, also known as surrogate basic attestation [UAFProtocol],
    /// the Authenticator does not have any specific attestation key pair. Instead it uses the
    /// credential private key to create the attestation signature. Authenticators without
    /// meaningful protection measures for an attestation private key typically use this
    /// attestation type.
    Self,
};
