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

/// Supported pinUvAuth protocols
token: struct {
    one: ?fido.ctap.pinuv.PinUvAuth = null,
    two: ?fido.ctap.pinuv.PinUvAuth = null,
},

allocator: std.mem.Allocator,

pub fn handle(self: *@This(), command: []const u8) Response {
    // Buffer for the response message
    var res = std.ArrayList(u8).init(self.allocator);
    var response = res.writer();
    response.writeByte(0x00) catch unreachable;

    // Decode the command of the given message
    if (command.len < 1) return Response{ .err = @enumToInt(StatusCodes.ctap1_err_invalid_length) };
    const cmd = Commands.fromRaw(command[0]) catch {
        res.deinit();
        return Response{ .err = @enumToInt(StatusCodes.ctap1_err_invalid_command) };
    };

    if (self.token.one) |*one| {
        one.pinUvAuthTokenUsageTimerObserver(self.callbacks.millis());
    }
    if (self.token.two) |*two| {
        two.pinUvAuthTokenUsageTimerObserver(self.callbacks.millis());
    }

    switch (cmd) {
        .authenticatorMakeCredential => {
            // Parse request
            var di = cbor.DataItem.new(command[1..]) catch {
                res.deinit();
                return Response{ .err = @enumToInt(StatusCodes.ctap2_err_invalid_cbor) };
            };

            const mcp = cbor.parse(fido.ctap.request.MakeCredential, di, .{
                .allocator = self.allocator,
            }) catch {
                res.deinit();
                return Response{ .err = @enumToInt(StatusCodes.ctap2_err_invalid_cbor) };
            };
            defer mcp.deinit(self.allocator);

            // Execute command
            const status = fido.ctap.commands.authenticator.authenticatorMakeCredential(
                self,
                &mcp,
                response,
            ) catch {
                res.deinit();
                return Response{ .err = @enumToInt(StatusCodes.ctap1_err_other) };
            };

            if (status != .ctap1_err_success) {
                res.deinit();
                return Response{ .err = @enumToInt(status) };
            }
        },
        .authenticatorGetInfo => {
            fido.ctap.commands.authenticator.authenticatorGetInfo(self.settings, response) catch {
                res.deinit();
                return Response{ .err = @enumToInt(StatusCodes.ctap2_err_not_allowed) };
            };
        },
        .authenticatorClientPin => {
            const status = fido.ctap.commands.authenticator.authenticatorClientPin(self, response, command) catch {
                res.deinit();
                return Response{ .err = @enumToInt(StatusCodes.ctap1_err_other) };
            };

            if (status != .ctap1_err_success) {
                res.deinit();
                return Response{ .err = @enumToInt(status) };
            }
        },
        else => {
            res.deinit();
            return Response{ .err = @enumToInt(StatusCodes.ctap2_err_not_allowed) };
        },
    }

    return Response{ .ok = res.toOwnedSlice() catch unreachable };
}

/// Returns true if the authenticator supports the given pinUvAuth protocol version
pub fn pinUvAuthProtocolSupported(
    self: *const @This(),
    protocol: fido.ctap.pinuv.common.PinProtocol,
) bool {
    if (self.settings.pinUvAuthProtocols == null) return false;

    var supported = false;

    // We must expose this capability via getInfo...
    for (self.settings.pinUvAuthProtocols.?) |prot| {
        if (prot == protocol) {
            supported = true;
            break;
        }
    }

    // ...and also provide the logic
    if (protocol == .V1 and self.token.one == null) {
        supported = false;
    } else if (protocol == .V2 and self.token.two == null) {
        supported = false;
    }

    return supported;
}

pub fn getClientPinOption(self: *const @This()) bool {
    if (self.settings.options) |options| {
        return if (options.clientPin) |cp| cp else false;
    }
    return false;
}

pub fn isProtected(self: *const @This()) bool {
    return self.callbacks.uv != null or self.token.one != null or self.token.two != null;
}
