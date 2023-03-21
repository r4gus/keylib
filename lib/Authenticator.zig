//! Representation of a FIDO2 authenticator.

const std = @import("std");
const data = @import("data.zig");
const commands = @import("commands.zig");
const Resources = @import("Resources.zig");
const cbor = @import("zbor");

/// Authenticator settings.
settings: data.Settings,

/// The type of attestation the authenticator should use.
attestation_type: data.AttestationType,

/// The pin uv auth token state.
/// This is mandatory for user authentication.
state: data.State = .{},

/// Resources provided by the underlying platform.
resources: Resources,

/// Supported signature algorithms.
sig_alg: []const cbor.cose.Algorithm,

//++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Public
//++++++++++++++++++++++++++++++++++++++++++++++++++++++

/// Get a new authenticator instance with default values
pub fn new_default(aaguid: [16]u8, resources: Resources) @This() {
    var auth = @This(){
        .settings = .{
            .versions = &[_]data.Versions{data.Versions.FIDO_2_1},
            .aaguid = aaguid,
            .options = .{
                .clientPin = true,
                .pinUvAuthToken = true,
                .alwaysUv = true,
            },
            .max_msg_size = 4096,
            .pin_uv_auth_protocols = &[_]data.client_pin.PinProtocol{.v2},
            .transports = &.{.usb},
            .min_pin_length = 4,
            .firmware_version = 0xcafe,
        },
        .attestation_type = .Self,
        .resources = resources,
        .sig_alg = &.{cbor.cose.Algorithm.Es256},
    };

    // Initialize the pin protocol state
    auth.state.initialize(auth.resources.rand);

    return auth;
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

    // Update pin token state based on time-outs
    self.state.pinUvAuthTokenUsageTimerObserver(self.resources.millis());

    // Load required authenticator data from memory
    var public_data = data.PublicData.load(self.resources.load, a) catch {
        data.PublicData.reset(
            self.resources.store,
            self.resources.rand,
            a,
            [_]u8{0} ** 12,
        );

        return handle_error(data.Errors.invalid_cbor, &res);
    };
    var write_back = true;
    defer {
        // TODO: this might ware out falsh memory
        if (write_back) {
            public_data.store(self.resources.store, a);
        }
    }

    switch (cmd) {
        .authenticator_make_credential => {
            var di = cbor.DataItem.new(command[1..]) catch {
                return handle_status(data.StatusCodes.ctap2_err_invalid_cbor, &res);
            };

            const make_credential_param = cbor.parse(
                data.make_credential.MakeCredentialParam,
                di,
                .{
                    .allocator = a,
                    .field_settings = &.{
                        .{ .name = "clientDataHash", .alias = "1", .options = .{} },
                        .{ .name = "rp", .alias = "2", .options = .{} },
                        .{ .name = "user", .alias = "3", .options = .{} },
                        .{ .name = "pubKeyCredParams", .alias = "4", .options = .{} },
                        .{ .name = "excludeList", .alias = "5", .options = .{} },
                        .{ .name = "options", .alias = "7", .options = .{} },
                        .{ .name = "pinUvAuthParam", .alias = "8", .options = .{} },
                        .{ .name = "pinUvAuthProtocol", .alias = "9", .options = .{} },
                    },
                },
            ) catch |err| {
                return handle_error(err, &res);
            };
            defer make_credential_param.deinit(a);

            var status: data.StatusCodes = data.StatusCodes.ctap1_err_success;

            status = commands.verify.verify_make_credential(
                self,
                &make_credential_param,
            ) catch |err| {
                return handle_error(err, &res);
            };

            if (status != .ctap1_err_success) {
                return handle_status(status, &res);
            }

            status = commands.authenticator_make_credential(
                self,
                &public_data,
                &make_credential_param,
                response,
                a,
            ) catch |err| {
                return handle_error(err, &res);
            };

            if (status != .ctap1_err_success) {
                return handle_status(status, &res);
            }
        },
        .authenticator_get_assertion => {
            var di = cbor.DataItem.new(command[1..]) catch {
                return handle_status(data.StatusCodes.ctap2_err_invalid_cbor, &res);
            };

            const get_assertion_param = cbor.parse(
                data.get_assertion.GetAssertionParam,
                di,
                .{
                    .allocator = a,
                    .field_settings = &.{
                        .{ .name = "rpId", .alias = "1", .options = .{} },
                        .{ .name = "clientDataHash", .alias = "2", .options = .{} },
                        .{ .name = "allowList", .alias = "3", .options = .{} },
                        .{ .name = "options", .alias = "5", .options = .{} },
                        .{ .name = "pinUvAuthParam", .alias = "6", .options = .{} },
                        .{ .name = "pinUvAuthProtocol", .alias = "7", .options = .{} },
                    },
                },
            ) catch |err| {
                return handle_error(err, &res);
            };
            defer get_assertion_param.deinit(a);

            var status: data.StatusCodes = data.StatusCodes.ctap1_err_success;

            status = commands.verify.verify_get_assertion(
                self,
                &get_assertion_param,
            ) catch |err| {
                return handle_error(err, &res);
            };

            if (status != .ctap1_err_success) {
                return handle_status(status, &res);
            }

            status = commands.authenticator_get_assertion(
                self,
                &public_data,
                &get_assertion_param,
                response,
                a,
            ) catch |err| {
                return handle_error(err, &res);
            };

            if (status != .ctap1_err_success) {
                return handle_status(status, &res);
            }
        },
        .authenticator_get_info => {
            commands.get_info(self.settings, response) catch |err| {
                return handle_error(err, &res);
            };
        },
        .authenticator_reset => {
            // Resetting an authenticator is a destructive operation!

            // Request permission from the user
            if (!self.resources.request_permission(null, null)) {
                return handle_status(data.StatusCodes.ctap2_err_operation_denied, &res);
            }

            data.PublicData.reset(
                self.resources.store,
                self.resources.rand,
                a,
                [_]u8{0} ** 12,
            );
            write_back = false;
        },
        .authenticator_client_pin => {
            const status = commands.authenticator_client_pin(
                self,
                &public_data,
                response,
                command,
                a,
            ) catch |err| {
                return handle_error(err, &res);
            };

            if (status != .ctap1_err_success) {
                return handle_status(status, &res);
            }
        },
        else => {},
    }

    return res.toOwnedSlice() catch unreachable;
}

//++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Private
//++++++++++++++++++++++++++++++++++++++++++++++++++++++

fn handle_status(status: data.StatusCodes, m: *std.ArrayList(u8)) []u8 {
    m.items[0] = @enumToInt(status);
    return m.toOwnedSlice() catch unreachable;
}

fn handle_error(err: data.Errors, m: *std.ArrayList(u8)) []u8 {
    return handle_status(data.StatusCodes.fromError(err), m);
}
