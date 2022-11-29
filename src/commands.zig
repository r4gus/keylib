const ErrorCodes = @import("error.zig").ErrorCodes;

pub const make_credential = @import("make_credential.zig");
pub const get_assertion = @import("get_assertion.zig");
pub const client_pin = @import("client_pin.zig");

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
    /// Vendor specific implementation.
    /// Command codes in the range between authenticatorVendorFirst and authenticatorVendorLast
    /// may be used for vendor-specific implementations. For example, the vendor may choose to
    /// put in some testing commands. Note that the FIDO client will never generate these commands.
    /// All other command codes are reserved for future use and may not be used.
    authenticator_vendor_first = 0x40,
    /// Vendor specific implementation.
    authenticator_vendor_last = 0xbf,

    pub fn fromRaw(byte: u8) ErrorCodes!Commands {
        switch (byte) {
            0x01 => return .authenticator_make_credential,
            0x02 => return .authenticator_get_assertion,
            0x04 => return .authenticator_get_info,
            0x06 => return .authenticator_client_pin,
            0x07 => return .authenticator_reset,
            0x08 => return .authenticator_get_next_assertion,
            0x40 => return .authenticator_vendor_first,
            0xbf => return .authenticator_vendor_last,
            else => return ErrorCodes.invalid_command,
        }
    }
};

/// Determine the command encoded by `data`.
pub fn getCommand(data: []const u8) ErrorCodes!Commands {
    if (data.len < 1) {
        return ErrorCodes.invalid_length;
    }

    return Commands.fromRaw(data[0]);
}

test "command tests" {
    _ = make_credential;
    _ = get_assertion;
    _ = client_pin;
}
