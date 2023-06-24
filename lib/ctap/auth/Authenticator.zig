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

/// A list of signature algorithms
///
/// This list should match the algorithms defined within the settings.
algorithms: []const fido.ctap.crypto.SigAlg,

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
        .authenticatorGetAssertion => {
            // Parse request
            var di = cbor.DataItem.new(command[1..]) catch {
                res.deinit();
                return Response{ .err = @enumToInt(StatusCodes.ctap2_err_invalid_cbor) };
            };

            const gap = cbor.parse(fido.ctap.request.GetAssertion, di, .{
                .allocator = self.allocator,
            }) catch {
                res.deinit();
                return Response{ .err = @enumToInt(StatusCodes.ctap2_err_invalid_cbor) };
            };
            defer gap.deinit(self.allocator);

            // Execute command
            const status = fido.ctap.commands.authenticator.authenticatorGetAssertion(
                self,
                &gap,
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
        .authenticatorReset => {
            // TODO: The authenticator instance should have a field that holds a time stamp
            // marking the point at wich the instance was created. One can then check if
            // the difference in time is less than 10 s.
            const up = self.callbacks.up(null, null);

            switch (up) {
                .Denied => {
                    res.deinit();
                    return Response{ .err = @enumToInt(StatusCodes.ctap2_err_operation_denied) };
                },
                .Timeout => {
                    res.deinit();
                    return Response{ .err = @enumToInt(StatusCodes.ctap2_err_user_action_timeout) };
                },
                .Accepted => {},
            }

            self.callbacks.reset();
        },
        .authenticatorSelection => {
            const status = fido.ctap.commands.authenticator.authenticatorSelection(self);

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

/// Get the state of the uv option
///
/// Returns false on default
pub fn getUvOption(self: *const @This()) bool {
    if (self.settings.options) |options| {
        return if (options.uv) |uv| uv else false;
    }
    return false;
}

/// Get the state of the pinUvAuthToken option
///
/// Returns false on default
pub fn getPinUvAuthTokenOption(self: *const @This()) bool {
    if (self.settings.options) |options| {
        return if (options.pinUvAuthToken) |t| t else false;
    }
    return false;
}

/// Get the state of the noMcGaPermissionsWithClientPin option
///
/// Returns false on default
pub fn getNoMcGaPermissionsWithClientPinOption(self: *const @This()) bool {
    if (self.settings.options) |options| {
        return options.noMcGaPermissionsWithClientPin;
    }
    return false;
}

/// Get the state of the up option
///
/// Returns true on default
pub fn getUpOption(self: *const @This()) bool {
    if (self.settings.options) |options| {
        return options.up;
    }
    return true;
}

/// Checks weather the authenticator is protected by some form of user verification
pub fn isProtected(self: *const @This()) bool {
    return self.buildInUvEnabled() or self.tokenSupportEnabled();
}

/// Returns true if build in user verification is enabled
pub fn buildInUvEnabled(self: *const @This()) bool {
    return self.getUvOption() and self.callbacks.uv != null;
}

/// Returns true if user verification via pinUvAuth token is enabled
pub fn tokenSupportEnabled(self: *const @This()) bool {
    return self.getPinUvAuthTokenOption() and (self.token.one != null or self.token.two != null);
}

/// Check if the given extension is supported
pub fn extensionSupported(self: *const @This(), ext: fido.ctap.extensions.Extension) bool {
    if (self.settings.extensions) |exts| {
        for (exts) |_ext| {
            if (_ext == ext) return true;
        }
    }
    return false;
}
