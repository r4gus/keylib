//! Representation of a FIDO2 authenticator.

const std = @import("std");
const data = @import("data.zig");
const commands = @import("commands.zig");
const Resources = @import("Resources.zig");

/// Authenticator settings.
settings: data.Settings,

/// The type of attestation the authenticator should use.
attestation_type: data.AttestationType,

/// The pin uv auth token state.
/// This is mandatory for user authentication.
state: data.State = .{},

/// Resources provided by the underlying platform
resources: Resources,

// TODO: sig_alg: []const SignatureAlgorithm

/// Get a new authenticator instance with default values
pub fn new_default(aaguid: [16]u8, resources: Resources) @This() {
    var auth = @This(){
        .settings = .{
            .versions = &[_]data.Versions{data.Versions.FIDO_2_1},
            .aaguid = aaguid,
            .options = .{
                .clientPin = true,
                .pinUvAuthToken = true,
            },
            .pin_uv_auth_protocols = &[_]data.client_pin.PinProtocol{.v2},
        },
        .attestation_type = .Self,
        .resources = resources,
    };

    // Initialize the pin protocol state
    auth.state.initialize(auth.resources.rand);

    return auth;
}

/// Main handler function, that takes a command and returns a response.
pub fn handle(self: *@This(), allocator: std.mem.Allocator, command: []const u8) ![]u8 {
    // The response message.
    // For encodings see: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#responses
    var res = std.ArrayList(u8).init(allocator);
    var response = res.writer();

    response.writeByte(0x00) catch { // just overwrite if neccessary
        res.items[0] = @enumToInt(data.StatusCodes.ctap1_err_other);
        return res.toOwnedSlice();
    };

    // Decode command
    const cmd = commands.getCommand(command) catch |err| {
        // On error, respond with a error code and return.
        res.items[0] = @enumToInt(data.StatusCodes.fromError(err));
        return res.toOwnedSlice();
    };

    switch (cmd) {
        .authenticator_get_info => {
            commands.get_info(self.settings, response) catch |err| {
                res.items[0] = @enumToInt(data.StatusCodes.fromError(err));
                return res.toOwnedSlice();
            };
        },
        else => {},
    }

    return res.toOwnedSlice();
}
