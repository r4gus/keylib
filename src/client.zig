const std = @import("std");
const client = @import("client");
const authenticatorGetInfo = client.cbor_commands.authenticatorGetInfo;
const client_pin = client.cbor_commands.client_pin;
const cred_management = client.cbor_commands.cred_management;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator = gpa.allocator();

pub fn main() !void {
    const pw = if (std.os.argv.len >= 2) blk: {
        var i: usize = 0;
        while (std.os.argv[1][i] != 0) : (i += 1) {}
        break :blk std.os.argv[1][0..i];
    } else {
        std.log.err("please provide a password", .{});
        return;
    };

    {
        // 1 The platform examines various option IDs in the authenti-
        //   catorGetInfo response to determine its course of action

        // Get all devices connect to the platform
        var transports = try client.Transports.enumerate(allocator, .{});
        defer transports.deinit();

        // Choose a device
        if (transports.devices.len == 0) {
            std.log.err("No device found, exiting...", .{});
            return;
        }

        var device = if (transports.devices.len == 1) blk: {
            break :blk &transports.devices[0];
        } else blk: {
            std.log.info("Please choose a device from the following list:", .{});
            for (transports.devices, 0..) |*device, i| {
                var x = try device.allocPrint(allocator);
                defer allocator.free(x);
                std.log.info("  {d} {s}", .{ i, x });
            }
            break :blk &transports.devices[0];
        };

        // Open a connection to the device
        try device.open();
        defer device.close();

        // Get information about the device and its capabilities
        const info = try authenticatorGetInfo(device, allocator);
        defer info.deinit(allocator);
        //std.log.info("info: {any}", .{info});

        // 1.a If the credMgmt option is not present or false, exit and
        //     fall back to manual selection.
        if ((info.options.credMgmt == null or !info.options.credMgmt.?) and
            (info.options.credentialMgmtPreview == null or !info.options.credentialMgmtPreview.?))
        {
            std.log.err("The selected device doesn't support credMgmt", .{});
            return;
        }

        // 1.b if both clientPin and uv option are either absent or false

        if (info.options.clientPin == null and info.options.uv == null) {
            std.log.err("The selected device doesn't support user verification", .{});
            return;
        }

        if (!info.options.clientPin.? and !info.options.uv.?) {
            std.log.err("No user verification set up for device", .{});
            return;
        }

        // 1.c if the uv option ID is present and set to true:
        var op: ?[]const u8 = null;

        if (info.options.uv != null and info.options.uv.?) {
            if (info.options.pinUvAuthToken != null and info.options.pinUvAuthToken.?) {
                op = "getPinUvAuthTokenUsingUvWithPermissions";
            }
        }

        if (op == null) {
            if (info.options.pinUvAuthToken != null and info.options.pinUvAuthToken.?) {
                if (info.options.clientPin != null and info.options.clientPin.?) {
                    op = "getPinUvAuthTokenUsingPinWithPermissions";
                }
            } else {
                if (info.options.clientPin != null and info.options.clientPin.?) {
                    op = "getPinToken";
                }
            }
        }

        if (op == null) {
            std.log.err("Selected authenticator doesn't support pinUvAuthToken", .{});
            return;
        }

        // 2 In preparation for obtaining pinUvAuthToken, the platform:

        // 2.a Obtains a shared secret

        if (info.pinUvAuthProtocols == null) {
            std.log.err("Device supports user verification but no pinUvAuthProtocols were returned as a result of calling getInfo", .{});
            return;
        }

        const pinUvAuthProtocol = info.pinUvAuthProtocols.?[0];

        var enc = try client_pin.getKeyAgreement(device, pinUvAuthProtocol, allocator);
        defer enc.deinit();
        std.log.info("shared secret: {any}", .{enc});

        // 3 Optain a pinUvAuthToken from the authenticator

        const token = if (std.mem.eql(u8, op.?, "getPinToken")) blk: {
            break :blk try client_pin.getPinToken(device, &enc, pw[0..], allocator);
        } else if (std.mem.eql(u8, op.?, "getPinUvAuthTokenUsingUvWithPermissions")) blk: {
            break :blk "";
        } else blk: {
            break :blk "";
        };
        defer allocator.free(token);
        std.log.info("token: {s}", .{std.fmt.fmtSliceHexLower(token)});

        // 4 the platform collects all RPs present on the given authenticator, removes RPs that
        //   are not supported IdPs, and then selects the IdP for authentication

        var rp = try cred_management.enumerateRPsBegin(device, pinUvAuthProtocol, token, allocator, true);
        if (rp) |_rp| {
            defer _rp.deinit();
            std.log.info("id: {s}", .{_rp.rp.id});

            var i: usize = 0;
            while (i < _rp.total.? - 1) : (i += 1) {
                if (try cred_management.enumerateRPsGetNextRP(device, allocator, true)) |rp2| {
                    defer rp2.deinit();
                    std.log.info("id: {s}", .{rp2.rp.id});
                }
            }
        } else {
            std.log.info("no RPs", .{});
        }

        // 5 if there has been a identity provider selected, authenticate
        //   through the selected IdP

        try client.cbor_commands.credentials.get(
            device,
            "https://github.com",
            false,
            .{
                .rpId = "github.com",
                .challenge = "\x01\x23\x45\x67\x89\xab",
            },
            .{
                .param = token,
                .protocol = pinUvAuthProtocol,
            },
            allocator,
        );
    }

    //if (gpa.detectLeaks()) {
    //    std.log.info("leak", .{});
    //}
}
