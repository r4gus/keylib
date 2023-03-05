const data = @import("data.zig");

pub const get_info = @import("commands/get_info.zig").get_info;

/// Commands supported by the CTAP protocol.
pub const Commands = enum(u8) {
    /// Request generation of a new credential in the authenticator.
    authenticator_make_credential = 0x01,
    /// Request cryptographic proof of user authentication as well as user consent to a given
    /// transaction, using a previously generated credential that is bound to the authenticator
    /// and relying party identifier.
    authenticator_get_assertion = 0x02,
    /// Request a list of all supported protocol versions, supported extensions, AAGUID of the
    /// device, and its capabilities
    authenticator_get_info = 0x04,
    /// Key agreement, setting a new PIN, changing a existing PIN, getting a `pinToken`.
    authenticator_client_pin = 0x06,
    /// Reset an authenticator back to factory default state, invalidating all generated credentials.
    authenticator_reset = 0x07,
    /// The client calls this method when the authenticatorGetAssertion response contains the
    /// `numberOfCredentials` member and the number of credentials exceeds 1.
    authenticator_get_next_assertion = 0x08,
    authenticator_bio_enrollment = 0x09,
    authenticator_credential_management = 0x0a,
    /// This command allows the platform to let a user select a certain authenticator by asking for user presence.
    authenticator_selection = 0x0b,
    /// This command allows a platform to store a larger amount of information associated with a credential.
    authenticator_large_blobs = 0x0c,
    /// This command is used to configure various authenticator features through the use of its subcommands.
    authenticator_config = 0x0d,
    /// Vendor specific implementation.
    /// Command codes in the range between authenticatorVendorFirst and authenticatorVendorLast
    /// may be used for vendor-specific implementations. For example, the vendor may choose to
    /// put in some testing commands. Note that the FIDO client will never generate these commands.
    /// All other command codes are reserved for future use and may not be used.
    authenticator_vendor_first = 0x40,
    /// Vendor specific implementation.
    authenticator_vendor_last = 0xbf,

    pub fn fromRaw(byte: u8) data.ErrorCodes!Commands {
        switch (byte) {
            0x01 => return .authenticator_make_credential,
            0x02 => return .authenticator_get_assertion,
            0x04 => return .authenticator_get_info,
            0x06 => return .authenticator_client_pin,
            0x07 => return .authenticator_reset,
            0x08 => return .authenticator_get_next_assertion,
            0x09 => return .authenticator_bio_enrollment,
            0x0a => return .authenticator_credential_management,
            0x0b => return .authenticator_selection,
            0x0c => return .authenticator_large_blobs,
            0x0d => return .authenticator_config,
            0x40 => return .authenticator_vendor_first,
            0xbf => return .authenticator_vendor_last,
            else => return data.ErrorCodes.invalid_command,
        }
    }
};

/// Determine the command encoded by `data`.
pub fn getCommand(d: []const u8) data.ErrorCodes!Commands {
    if (d.len < 1) {
        return data.ErrorCodes.invalid_length;
    }

    return Commands.fromRaw(d[0]);
}
