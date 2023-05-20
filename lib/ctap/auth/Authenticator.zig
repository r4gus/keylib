//! Representation of a FIDO2 authenticator

const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");

const Response = fido.ctap.authenticator.Response;
const StatusCodes = fido.ctap.StatusCodes;
const Commands = fido.ctap.commands.Commands;

/// Authenticator settings that represent the authenticators capabilities
settings: fido.ctap.authenticator.Settings,

/// The type of attestation the authenticator supports
attestation_type: fido.common.AttestationType,

/// Callbacks provided by the underlying platform
callbacks: fido.ctap.authenticator.Callbacks,

allocator: std.mem.Allocator,

pub fn handle(self: *@This(), command: []const u8) Response {
    // Buffer for the response message
    var res = std.ArrayList(u8).init(self.allocator);
    var response = res.writer();
    response.writeByte(0x00) catch unreachable;
    errdefer res.deinit();

    // Decode the command of the given message
    if (command.len < 1) return Response{ .err = @enumToInt(StatusCodes.ctap1_err_invalid_length) };
    const cmd = Commands.fromRaw(command[0]) catch {
        return Response{ .err = @enumToInt(StatusCodes.ctap1_err_invalid_command) };
    };

    switch (cmd) {
        .authenticatorGetInfo => {
            fido.ctap.commands.authenticator.authenticatorGetInfo(self.settings, response) catch {
                return Response{ .err = @enumToInt(StatusCodes.ctap2_err_not_allowed) };
            };
        },
        else => return Response{ .err = @enumToInt(StatusCodes.ctap2_err_not_allowed) },
    }

    return Response{ .ok = res.toOwnedSlice() catch unreachable };
}
