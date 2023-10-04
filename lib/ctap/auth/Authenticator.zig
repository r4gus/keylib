//! Representation of a FIDO2 authenticator

const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");

const Allocator = std.mem.Allocator;

const Callbacks = fido.ctap.authenticator.callbacks.Callbacks;
const Data = fido.ctap.authenticator.callbacks.Data;
const DataIterator = fido.ctap.authenticator.callbacks.DataIterator;
const Error = fido.ctap.authenticator.callbacks.Error;
const Settings = fido.ctap.authenticator.Settings;
const PinUvAuth = fido.ctap.pinuv.PinUvAuth;
const SigAlg = fido.ctap.crypto.SigAlg;
const AttestationType = fido.common.AttestationType;

const Response = fido.ctap.authenticator.Response;
const StatusCodes = fido.ctap.StatusCodes;
const Commands = fido.ctap.commands.Commands;

pub const Auth = struct {
    /// Callbacks provided by the underlying platform
    callbacks: Callbacks,

    /// Authenticator settings that represent the authenticators capabilities
    settings: Settings,

    /// Pin uv auth protocol
    token: PinUvAuth,

    /// A list of signature algorithms
    ///
    /// This list should match the algorithms defined within the settings.
    algorithms: []const fido.ctap.crypto.SigAlg,

    attestation: AttestationType = .Self,

    allocator: Allocator,

    pub fn default(callbacks: Callbacks, allocator: Allocator) @This() {
        return .{
            .callbacks = callbacks,
            .settings = .{
                .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
                .extensions = &.{.credProtect},
                .aaguid = "\x6f\x15\x82\x74\xaa\xb6\x44\x3d\x9b\xcf\x8a\x3f\x69\x29\x7c\x88".*,
                .options = .{
                    .credMgmt = true,
                    .rk = true,
                    .uv = if (callbacks.uv) |_| true else null,
                    // This is a platform authenticator even if we use usb for ipc
                    .plat = true,
                    // We don't support client pin
                    .clientPin = null,
                    .pinUvAuthToken = true,
                    .alwaysUv = false,
                },
                .pinUvAuthProtocols = &.{.V2},
                .transports = &.{.usb},
                .algorithms = &.{.{ .alg = .Es256 }},
                .firmwareVersion = 0xcafe,
                .remainingDiscoverableCredentials = 100,
            },
            .token = PinUvAuth.v2(std.crypto.random),
            .algorithms = &.{
                fido.ctap.crypto.algorithms.Es256,
            },
            .allocator = allocator,
        };
    }

    pub fn init(self: *@This()) !void {
        // Check that settings are available and if not, create them
        const meta = self.loadSettings() catch |e| blk: {
            if (e == error.NoData) {
                std.log.info("Auth.init: no settings found", .{});
            } else {
                std.log.err("Auth.init: malformed settings", .{});
            }

            std.log.info("Auth.init: generating new settings...", .{});
            var meta = fido.ctap.authenticator.Meta{};
            self.writeSettings(meta) catch {
                std.log.err("Auth.init: unable to persist settings", .{});
                return error.InitFail;
            };

            std.log.info("Auth.init: new settings persisted", .{});
            break :blk meta;
        };
        _ = meta;

        // Initialize piNUv
        self.token.initialize();
    }

    /// Try to load settings
    pub fn loadSettings(self: *@This()) !fido.ctap.authenticator.Meta {
        const id: [:0]const u8 = "Settings";
        const rp: [:0]const u8 = "Root";
        var iter = DataIterator{
            .allocator = self.allocator,
        };
        defer iter.deinit();

        if (self.callbacks.read(id, rp, &iter.d) != Error.SUCCESS) {
            return error.NoData;
        }

        if (iter.next()) |s| {
            // Turn data hex string into a byte slice
            var buffer: [256]u8 = .{0} ** 256;
            const slice = try std.fmt.hexToBytes(&buffer, s);

            return try cbor.parse(
                fido.ctap.authenticator.Meta,
                try cbor.DataItem.new(slice),
                .{},
            );
        } else {
            return error.NoData;
        }
    }

    /// Write settings back into permanent storage
    pub fn writeSettings(self: *@This(), meta: fido.ctap.authenticator.Meta) !void {
        const id: [:0]const u8 = "Settings";
        const rp: [:0]const u8 = "Root";
        var str = std.ArrayList(u8).init(self.allocator);
        defer str.deinit();

        try cbor.stringify(meta, .{}, str.writer());

        // Covert the data into a hex string
        var str2 = std.ArrayList(u8).init(self.allocator);
        defer str2.deinit();
        try str2.writer().print("{s}", .{std.fmt.fmtSliceHexLower(str.items)});

        if (self.callbacks.write(id, rp, str2.items.ptr, @intCast(str2.items.len)) != Error.SUCCESS) {
            return error.Write;
        }
    }

    pub fn handle(self: *@This(), command: []const u8) Response {
        // Buffer for the response message
        var res = std.ArrayList(u8).init(self.allocator);
        var response = res.writer();
        response.writeByte(0x00) catch unreachable;

        // Decode the command of the given message
        if (command.len < 1) return Response{ .err = @intFromEnum(StatusCodes.ctap1_err_invalid_length) };
        const cmd = Commands.fromRaw(command[0]) catch {
            res.deinit();
            return Response{ .err = @intFromEnum(StatusCodes.ctap1_err_invalid_command) };
        };

        switch (cmd) {
            .authenticatorGetInfo => {
                const status = fido.ctap.commands.authenticator.authenticatorGetInfo(self, response) catch {
                    res.deinit();
                    return Response{ .err = @intFromEnum(StatusCodes.ctap1_err_other) };
                };

                if (status != .ctap1_err_success) {
                    res.deinit();
                    return Response{ .err = @intFromEnum(status) };
                }
            },
            else => {
                res.deinit();
                return Response{ .err = @intFromEnum(StatusCodes.ctap2_err_not_allowed) };
            },
        }

        return Response{ .ok = res.toOwnedSlice() catch unreachable };
    }
};
