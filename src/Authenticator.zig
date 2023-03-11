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
            .max_msg_size = 4096,
            .pin_uv_auth_protocols = &[_]data.client_pin.PinProtocol{.v2},
            .transports = &.{.usb},
            .min_pin_length = 4,
            .firmware_version = 0xcafe,
        },
        .attestation_type = .Self,
        .resources = resources,
    };

    // Initialize the pin protocol state
    auth.state.initialize(auth.resources.rand);

    return auth;
}

fn handle_error(err: data.Errors, m: *std.ArrayList(u8)) []u8 {
    m.items[0] = @enumToInt(data.StatusCodes.fromError(err));
    return m.toOwnedSlice() catch unreachable;
}

/// Main handler function, that takes a command and returns a response.
pub fn handle(self: *@This(), command: []const u8) []u8 {
    const Mem = struct {
        // The user shouldn't be tasked with deciding how much
        // memory the app requires.
        threadlocal var m: [8096]u8 = undefined;
    };
    var fba = std.heap.FixedBufferAllocator.init(&Mem.m);
    const a = fba.allocator();

    // The response message.
    var res = std.ArrayList(u8).init(a);
    var response = res.writer();
    response.writeByte(0x00) catch unreachable; // we have enough memory available

    // Decode command
    const cmd = commands.getCommand(command) catch |err| {
        return handle_error(err, &res);
    };

    switch (cmd) {
        .authenticator_get_info => {
            commands.get_info(self.settings, response) catch |err| {
                return handle_error(err, &res);
            };
        },
        else => {},
    }

    return res.toOwnedSlice() catch unreachable;
}
