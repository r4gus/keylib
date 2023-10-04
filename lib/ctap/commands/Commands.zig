/// Commands supported by the CTAP protocol.
pub const Commands = enum(u8) {
    /// Request generation of a new credential in the authenticator.
    authenticatorMakeCredential = 0x01,
    /// Request cryptographic proof of user authentication as well as user consent to a given
    /// transaction, using a previously generated credential that is bound to the authenticator
    /// and relying party identifier.
    authenticatorGetAssertion = 0x02,
    /// Request a list of all supported protocol versions, supported extensions, AAGUID of the
    /// device, and its capabilities
    authenticatorGetInfo = 0x04,
    /// Key agreement, setting a new PIN, changing a existing PIN, getting a `pinToken`.
    authenticatorClientPin = 0x06,
    /// Reset an authenticator back to factory default state, invalidating all generated credentials.
    authenticatorReset = 0x07,
    /// The client calls this method when the authenticatorGetAssertion response contains the
    /// `numberOfCredentials` member and the number of credentials exceeds 1.
    authenticatorGetNextAssertion = 0x08,
    authenticatorBioEnrollment = 0x09,
    authenticatorCredentialManagement = 0x0a,
    /// This command allows the platform to let a user select a certain authenticator by asking for user presence.
    authenticatorSelection = 0x0b,
    /// This command allows a platform to store a larger amount of information associated with a credential.
    authenticatorLargeBlobs = 0x0c,
    /// This command is used to configure various authenticator features through the use of its subcommands.
    authenticatorConfig = 0x0d,
    /// Vendor specific implementation.
    /// Command codes in the range between authenticatorVendorFirst and authenticatorVendorLast
    /// may be used for vendor-specific implementations. For example, the vendor may choose to
    /// put in some testing commands. Note that the FIDO client will never generate these commands.
    /// All other command codes are reserved for future use and may not be used.
    authenticatorVendorFirst = 0x40,
    authenticatorCredentialManagementYubico = 0x41,
    /// Vendor specific implementation.
    authenticatorVendorLast = 0xbf,

    pub fn fromRaw(byte: u8) !Commands {
        switch (byte) {
            0x01 => return .authenticatorMakeCredential,
            0x02 => return .authenticatorGetAssertion,
            0x04 => return .authenticatorGetInfo,
            0x06 => return .authenticatorClientPin,
            0x07 => return .authenticatorReset,
            0x08 => return .authenticatorGetNextAssertion,
            0x09 => return .authenticatorBioEnrollment,
            0x0a => return .authenticatorCredentialManagement,
            0x0b => return .authenticatorSelection,
            0x0c => return .authenticatorLargeBlobs,
            0x0d => return .authenticatorConfig,
            0x40 => return .authenticatorVendorFirst,
            0x41 => return .authenticatorCredentialManagementYubico,
            0xbf => return .authenticatorVendorLast,
            else => return error.InvalidCommand,
        }
    }
};
