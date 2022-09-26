/// Client to Authenticator (CTAP) library
const std = @import("std");
const cbor = @import("zbor");
const testing = std.testing;
const DataItem = cbor.DataItem;
const Pair = cbor.Pair;

/// CTAP status codes.
const StatusCodes = enum(u8) {
    /// Indicates successful response.
    ctap1_err_success = 0x00,
    /// The command is not a valid CTAP command.
    ctap1_err_invalid_command = 0x01,
    /// The command included an invalid parameter.
    ctap1_err_invalid_parameter = 0x02,
    /// Invalid message or item length.
    ctap1_err_invalid_length = 0x03,
    /// Invalid message sequencing.
    ctap1_err_invalid_seq = 0x04,
    /// Message timed out.
    ctap1_err_tiemout = 0x05,
    /// Channel busy.
    ctap1_err_channel_busy = 0x06,
    /// Command requires channel lock.
    ctap1_err_lock_required = 0x0a,
    /// Command not allowed on this cid.
    ctap1_err_invalid_channel = 0x0b,
    /// Invalid/ unexpected CBOR error.
    ctap2_err_cbor_unexpected_type = 0x11,
    /// Error when parsing CBOR.
    ctap2_err_invalid_cbor = 0x12,
    /// Missing non-optional parameter.
    ctap2_err_missing_parameter = 0x14,
    /// Limit for number of items exceeded.
    ctap2_err_limit_exceeded = 0x15,
    /// Unsupported extension.
    ctap2_err_unsupported_extension = 0x16,
    /// Valid credential found in the excluded list.
    ctap2_err_credential_excluded = 0x19,
    /// Processing (Lenghty operation is in progress).
    ctap2_err_processing = 0x21,
    /// Credential not valid for the authenticator.
    ctap2_err_invalid_credential = 0x22,
    /// Authenticator is waiting for user interaction.
    ctap2_err_user_action_pending = 0x23,
    /// Processing, lengthy operation is in progress.
    ctap2_err_operation_pending = 0x24,
    /// No request is pending.
    ctap2_err_no_operations = 0x25,
    /// Authenticator does not support requested algorithm.
    ctap2_err_unsupported_algorithm = 0x26,
    /// Not authorized for requested operation.
    ctap2_err_operation_denied = 0x27,
    /// Internal key storage is full.
    ctap2_err_key_store_full = 0x28,
    /// Authenticator cannot cancel as it is not busy.
    ctap2_err_not_busy = 0x29,
    /// No outstanding operations.
    ctap2_err_no_operation_pending = 0x2a,
    /// Unsupported option.
    ctap2_err_unsupported_option = 0x2b,
    /// Not a valid option for current operation.
    ctap2_err_invalid_option = 0x2c,
    /// Pending keep alive was canceled.
    ctap2_err_keepalive_cancel = 0x2d,
    /// No valid credentials provided.
    ctap2_err_no_credentials = 0x2e,
    /// Timeout waiting for user interaction.
    ctap2_err_user_action_timeout = 0x2f,
    /// Continuation command, such as, `authenticatorGetNexAssertion` not allowed.
    ctap2_err_not_allowed = 0x30,
    /// PIN invalid.
    ctap2_err_pin_invalid = 0x31,
    /// PIN blocked.
    ctap2_err_pin_blocked = 0x32,
    /// PIN authentication (`pinAuth`) verification failed.
    ctap2_err_pin_auth_invalid = 0x33,
    /// PIN authentication (`pinAuth`) blocked. Requires power recycle to reset.
    ctap2_err_pin_auth_blocked = 0x34,
    /// No PIN has been set.
    ctap2_err_pin_not_set = 0x35,
    /// PIN is required for the selected operation.
    ctap2_err_pin_required = 0x36,
    /// PIN policy violation. Currently only enforces minimum length.
    ctap2_err_pin_policy_violation = 0x37,
    /// `pinToken` expired on authenticator.
    ctap2_err_pin_token_expired = 0x38,
    /// Authenticator cannot handle this request due to memory constraints.
    ctap2_err_request_too_large = 0x39,
    /// The current operation has timed out.
    ctap2_err_action_timeout = 0x3a,
    /// User presence is required for the requested operation.
    ctap2_err_up_required = 0x3b,
    /// Other unspecified error.
    ctap1_err_other = 0x7f,
    /// CTAP 2 spac last error.
    ctap2_err_spec_last = 0xdf,
    /// Extension specific error.
    ctap2_err_extension_first = 0xe0,
    /// Extension specific error.
    ctap2_err_extension_last = 0xef,
    /// Vendor specific error.
    ctap2_err_vendor_first = 0xf0,
    /// Vendor specific error.
    ctap2_err_vendor_last = 0xff,

    pub fn fromError(err: ErrorCodes) @This() {
        return switch (err) {
            ErrorCodes.invalid_command => .ctap1_err_invalid_command,
            ErrorCodes.invalid_length => .ctap1_err_invalid_length,
        };
    }
};

const ErrorCodes = error{
    /// The command is not a valid CTAP command.
    invalid_command,
    /// Invalid message or item length.
    invalid_length,
};

/// Commands supported by the CTAP protocol.
const Commands = enum(u8) {
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

/// Supported version of the authenticator.
const Versions = enum {
    /// For CTAP2/FIDO2/Web Authentication authenticators.
    fido_2_0,
    /// For CTAP1/U2F authenticators.
    u2f_v2,

    pub fn toString(self: @This()) []const u8 {
        return switch (self) {
            .fido_2_0 => "FIDO_2_0",
            .u2f_v2 => "U2F_V2",
        };
    }
};

const Extensions = enum {};

/// Authenticator options.
///
/// When an option is not present, the default is applied.
const Options = struct {
    /// Platform device: Indicates that the device is attached to the client
    /// and therefore can't be removed and used on another client.
    plat: ?bool,
    /// Resident key: Indicates that the device is capable of storing keys on
    /// the device itself and therefore can satisfy the `authenticatorGetAssertion`
    /// request with `allowList` parameter not specified or empty.
    rk: ?bool,
    /// present + true: device is capable of accepting a PIN from the client and
    ///                 PIN has been set
    /// present + false: device is capable of accepting a PIN from the client and
    ///                  PIN has not been set yet.
    /// absent: indicates that the device is not capable of accepting a PIN from the client.
    client_pin: ?bool,
    /// User presence.
    /// true: indicates that the device is capable of testing user presence.
    up: ?bool,
    /// User verification: Device is capable of verifiying the user within itself.
    /// present + true: device is capable of user verification within itself and
    ///                 has been configured.
    /// present + false: device is capable of user verification within itself and
    ///                  has not been yet configured.
    /// absent: device is not capable of user verification within itself.
    ///
    /// A device that can only do Client PIN will not return the "uv" parameter.
    uv: ?bool,

    pub fn default() @This() {
        return @This(){
            .plat = false,
            .rk = false,
            .client_pin = null,
            .up = true,
            .uv = null,
        };
    }
};

/// Available PIN protocol versions.
const PinProtocols = enum(u8) {
    /// PIN Protocol Version 1.
    v1 = 1,
};

/// Determine the command encoded by `data`.
fn getCommand(data: []const u8) ErrorCodes!Commands {
    if (data.len < 1) {
        return ErrorCodes.invalid_length;
    }

    return Commands.fromRaw(data[0]);
}

/// Abstract representation of a CTAP authenticator.
const Authenticator = struct {
    /// List of supported versions.
    versions: []Versions,
    /// List of supported extensions.
    extensions: []Extensions,
    /// The Authenticator Attestation GUID (AAGUID) is a 128-bit identifier
    /// indicating the type of the authenticator. Authenticators with the
    /// same capabilities and firmware, can share the same AAGUID.
    aaguid: [16]u8,
    /// Supported options.
    options: Options,
    /// Maximum message size supported by the authenticator.
    /// null = unlimited.
    max_msg_size: ?usize,
    /// List of supported PIN Protocol versions.
    pin_protocols: ?[]u8,

    /// Default initialization without extensions.
    pub fn initDefault(versions: []Versions, aaguid: [16]u8) @This() {
        return @This(){
            .versions = versions,
            .extensions = &.{},
            .aaguid = aaguid,
            .options = Options.default(),
            .max_msg_size = null,
            .pin_protocols = null,
        };
    }

    /// Main handler function, that takes a command and returns a response.
    pub fn handle(self: *const @This(), command: []const u8, response: anytype) !void {
        const cmdnr = getCommand(command) catch |err| {
            // On error, respond with a error code and return.
            try response.writeByte(@enumToInt(StatusCodes.fromError(err)));
            return;
        };

        switch (cmdnr) {
            .authenticator_make_credential => {},
            .authenticator_get_assertion => {},
            .authenticator_get_info => {
                // One can't reclaim allocated memory of an fba but it gets
                // dropped at the end of this block anyway, so fuck it...
                // no need to deinit the (nested) data item.
                var buffer: [2048]u8 = undefined;
                var fba = std.heap.FixedBufferAllocator.init(&buffer);
                const allocator = fba.allocator();

                var di = try DataItem.map(allocator, &.{Pair.new(try DataItem.text(allocator, "aaguid"), try DataItem.bytes(allocator, &self.aaguid))});

                try cbor.encode(response, &di);
            },
            .authenticator_client_pin => {},
            .authenticator_reset => {},
            .authenticator_get_next_assertion => {},
            .authenticator_vendor_first => {},
            .authenticator_vendor_last => {},
        }
    }
};

export fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "fetch command from data" {
    try std.testing.expectError(ErrorCodes.invalid_length, getCommand(""));
    try std.testing.expectEqual(Commands.authenticator_make_credential, try getCommand("\x01"));
    try std.testing.expectEqual(Commands.authenticator_get_assertion, try getCommand("\x02"));
    try std.testing.expectEqual(Commands.authenticator_get_info, try getCommand("\x04"));
    try std.testing.expectEqual(Commands.authenticator_client_pin, try getCommand("\x06"));
    try std.testing.expectEqual(Commands.authenticator_reset, try getCommand("\x07"));
    try std.testing.expectEqual(Commands.authenticator_get_next_assertion, try getCommand("\x08"));
    try std.testing.expectEqual(Commands.authenticator_vendor_first, try getCommand("\x40"));
    try std.testing.expectEqual(Commands.authenticator_vendor_last, try getCommand("\xbf"));
    try std.testing.expectError(ErrorCodes.invalid_command, getCommand("\x03"));
    try std.testing.expectError(ErrorCodes.invalid_command, getCommand("\x09"));
}

test "version enum to string" {
    try std.testing.expectEqualStrings("FIDO_2_0", Versions.fido_2_0.toString());
    try std.testing.expectEqualStrings("U2F_V2", Versions.u2f_v2.toString());
}

test "default Authenticator initialization" {
    var allocator = std.testing.allocator;

    var v = try allocator.alloc(Versions, 1);
    defer allocator.free(v);
    v[0] = .fido_2_0;

    const auth = Authenticator.initDefault(v, [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });

    try std.testing.expectEqual(Versions.fido_2_0, auth.versions[0]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, &auth.aaguid);
    try std.testing.expectEqual(false, auth.options.plat.?);
    try std.testing.expectEqual(false, auth.options.rk.?);
    try std.testing.expectEqual(null, auth.options.client_pin);
    try std.testing.expectEqual(true, auth.options.up.?);
    try std.testing.expectEqual(null, auth.options.uv);
    try std.testing.expectEqual(null, auth.max_msg_size);
    try std.testing.expectEqual(null, auth.pin_protocols);
}

test "get info from authenticator" {
    var allocator = std.testing.allocator;

    var arr = std.ArrayList(u8).init(allocator);
    arr.deinit();

    var v = try allocator.alloc(Versions, 1);
    defer allocator.free(v);
    v[0] = .fido_2_0;
    const auth = Authenticator.initDefault(v, [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });

    try auth.handle("\x04", arr.writer());

    try std.testing.expectEqualStrings("", arr.items);
}
