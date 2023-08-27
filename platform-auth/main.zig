const std = @import("std");
const cks = @import("cks");
const fido = @import("fido");
const hid = @import("hid.zig");
const profiling_allocator = @import("profiling_allocator");
const snorlax = @import("snorlax");

const notify = @cImport({
    @cInclude("libnotify/notify.h");
});

const uhid = @cImport(
    @cInclude("linux/uhid.h"),
);

const signal = @cImport(
    @cInclude("signal.h"),
);

var store: ?cks.CKS = null;

var device: std.fs.File = undefined;

var authenticator: fido.ctap.authenticator.Authenticator = undefined;

var uv: ?bool = null;

var notification: [*c]notify.NotifyNotification = undefined;

var quit: bool = false;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

fn intHandler(dummy: c_int) callconv(.C) void {
    _ = dummy;
    std.log.info("shutting down keepass", .{});
    quit = true;
    notify.g_main_context_wakeup(null);
}

fn accept_callback(
    n: [*c]notify.NotifyNotification,
    action: [*c]u8,
    p: notify.gpointer,
) callconv(.C) void {
    _ = n;
    _ = action;
    _ = p;
    uv = true;
    notify.g_print("accept function called\n");
    //notify.g_main_loop_quit(loop);
}

fn decline_callback(
    n: [*c]notify.NotifyNotification,
    action: [*c]u8,
    p: notify.gpointer,
) callconv(.C) void {
    _ = n;
    _ = action;
    _ = p;
    uv = false;
    notify.g_print("decline function called\n");
    //notify.g_main_loop_quit(loop);
}

fn packet_callback(user_data: notify.gpointer) callconv(.C) notify.gboolean {
    _ = user_data;

    var event = std.mem.zeroes(uhid.uhid_event);
    const l = device.read(std.mem.asBytes(&event)) catch {
        return 1;
    };
    _ = l;

    switch (event.type) {
        uhid.UHID_START => {
            //std.log.info("START\n", .{});
        },
        uhid.UHID_STOP => {
            //std.log.info("STOP\n", .{});
        },
        uhid.UHID_OPEN => {
            //std.log.info("OPEN\n", .{});
        },
        uhid.UHID_CLOSE => {
            //std.log.info("CLOSE\n", .{});
        },
        uhid.UHID_OUTPUT => {
            //std.log.info("OUTPUT\n", .{});
            //std.log.info("{x}\n", .{std.fmt.fmtSliceHexLower(event.u.output.data[1..event.u.output.size])});

            var response = fido.ctap.transports.ctaphid.authenticator.handle(
                event.u.output.data[1..event.u.output.size],
                &authenticator,
            );

            if (response) |*resp| {
                // Free the response data at the end
                defer resp.deinit();

                while (resp.next()) |packet| {
                    var rev = std.mem.zeroes(uhid.uhid_event);
                    rev.type = uhid.UHID_INPUT;
                    @memcpy(rev.u.input.data[0..packet.len], packet);
                    rev.u.input.size = @as(c_ushort, @intCast(packet.len));

                    //std.debug.print("-> {s}\n", .{std.fmt.fmtSliceHexUpper(packet[0..])});

                    uhid_write(device, &rev) catch {
                        std.log.err("failed to send CTAPHID packet\n", .{});
                    };
                }
            }
        },
        else => {},
    }

    return 1;
}

pub fn main() !void {
    const interval_ms: notify.guint = 10;
    var source = notify.g_timeout_source_new(interval_ms);
    notify.g_source_set_callback(source, &packet_callback, null, null);
    _ = notify.g_source_attach(source, null);

    _ = notify.notify_init("Hello world!");
    defer notify.notify_uninit();

    var context: ?*notify.GMainContext = notify.g_main_context_default();

    // Here we register the interrupt handler for (ctrl + c). This will
    // allow us to break out of the main loop by setting quit to false.
    _ = signal.signal(signal.SIGINT, intHandler);

    // ------------------- Setup USB HID ----------------------
    const path = "/dev/uhid";
    device = std.fs.openFileAbsolute(path, .{
        .mode = .read_write,
    }) catch {
        std.log.err("Can't open uhid-cdev {s}\n", .{path});
        return;
    };
    defer device.close();
    const flags = try std.os.fcntl(device.handle, 3, 0);
    _ = try std.os.fcntl(device.handle, 4, flags | 2048);

    try create(device);
    defer destroy(device) catch unreachable;
    // --------------------------------------------------------

    // ------------------- Initialize authenticator -----------
    authenticator = fido.ctap.authenticator.Authenticator{
        .settings = .{
            .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
            .extensions = &.{.credProtect},
            .aaguid = "\x6f\x15\x82\x74\xaa\xb6\x44\x3d\x9b\xcf\x8a\x3f\x69\x29\x7c\x88".*,
            .options = .{
                .credMgmt = true,
                .rk = true,
                .uv = false,
                // This is a platform authenticator even if we use usb for ipc
                .plat = true,
                // Set clientPin to false if you wanna support a pin and to none
                // if you don't want to use a pin at all.
                .clientPin = false,
                .pinUvAuthToken = true,
                .alwaysUv = true,
            },
            .pinUvAuthProtocols = &.{.V2},
            .transports = &.{.usb},
            .algorithms = &.{.{ .alg = .Es256 }},
            .firmwareVersion = 0xcafe,
            .remainingDiscoverableCredentials = 100,
        },
        .attestation_type = .Self,
        .callbacks = .{
            .rand = std.crypto.random,
            .millis = std.time.milliTimestamp,
            .up = up,
            .readSettings = readSettings,
            .updateSettings = updateSettings,
            .readCred = readCred,
            .updateCred = updateCred,
            .deleteCred = deleteCred,
            .reset = reset,
        },
        .algorithms = &.{
            fido.ctap.crypto.algorithms.Es256,
        },
        .token = .{
            //.one = fido.ctap.pinuv.PinUvAuth.v1(callbacks.rand),
            .two = fido.ctap.pinuv.PinUvAuth.v2(std.crypto.random),
        },
        .allocator = allocator,
    };

    try authenticator.init("password");
    defer authenticator.deinit();
    // --------------------------------------------------------

    //notify.g_main_loop_run(loop);
    while (!quit) {
        _ = notify.g_main_context_iteration(context, 1);
    }

    _ = gpa.detectLeaks();
}

// +++++++++++++++++++++++++++++++++++++++++++++
// Callbacks
// +++++++++++++++++++++++++++++++++++++++++++++

const LoadError = fido.ctap.authenticator.Callbacks.LoadError;
const UpResult = fido.ctap.authenticator.Callbacks.UpResult;
const UpReason = fido.ctap.authenticator.Callbacks.UpReason;

pub fn password(pw: ?[]const u8) ?[]const u8 {
    const S = struct {
        pub var s: ?[]const u8 = null;
    };

    if (pw != null) {
        S.s = pw.?;
    }

    return S.s;
}

/// Get the epoch time in ms
pub fn millis() u64 {
    return @as(u64, @intCast(std.time.milliTimestamp()));
}

pub fn up(reason: UpReason, user: ?*const fido.common.User, rp: ?*const fido.common.RelyingParty) UpResult {
    uv = null; // reset flag

    const uid = if (user) |u| u.id else "unknown user";
    const rpid = if (rp) |r| r.id else "unknown relying party";
    _ = uid;

    const r = switch (reason) {
        .MakeCredential => std.fmt.allocPrintZ(allocator, "Credential creation request for {s}.", .{rpid}) catch unreachable,
        .GetAssertion => std.fmt.allocPrintZ(allocator, "Authentication request for {s}.", .{rpid}) catch unreachable,
        .AuthenticatorSelection => std.fmt.allocPrintZ(allocator, "Please confirm if you want to select this authenticator.", .{}) catch unreachable,
        .Reset => std.fmt.allocPrintZ(allocator, "Do you really want to reset the your authenticator?", .{}) catch unreachable,
    };
    defer allocator.free(r);

    notification = notify.notify_notification_new("PassKee user presence", @ptrCast(r), "dialog-information");
    notify.notify_notification_set_hint(notification, "transient", notify.g_variant_new_boolean(1));
    notify.notify_notification_set_urgency(notification, notify.NOTIFY_URGENCY_CRITICAL);
    notify.notify_notification_set_timeout(notification, notify.NOTIFY_EXPIRES_DEFAULT);
    notify.notify_notification_add_action(
        notification,
        "accept",
        "Accept",
        notify.NOTIFY_ACTION_CALLBACK(accept_callback),
        null,
        null,
    );
    notify.notify_notification_add_action(
        notification,
        "decline",
        "Decline",
        notify.NOTIFY_ACTION_CALLBACK(decline_callback),
        null,
        null,
    );
    notify.notify_notification_set_category(notification, "device");
    _ = notify.notify_notification_show(notification, null);

    const up_start = std.time.timestamp();

    while (true) {
        _ = notify.g_main_context_iteration(null, 0);
        if (uv) |accepted| {
            if (accepted) {
                return .Accepted;
            } else {
                return .Denied;
            }
        }

        if ((std.time.timestamp() - up_start) > 10) break;
    }

    return .Timeout;
}

pub fn reset() void {}

pub fn readSettings(
    a: std.mem.Allocator,
) fido.ctap.authenticator.Callbacks.LoadError!fido.ctap.authenticator.Meta {
    var buffer: [50000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const all = fba.allocator();

    var client = snorlax.Snorlax.init("127.0.0.1", 5984, "admin", "fido", all) catch {
        return fido.ctap.authenticator.Callbacks.LoadError.Other;
    };
    defer client.deinit();

    var meta = client.read(fido.ctap.authenticator.Meta, "passkee", "Settings", a) catch |err| {
        if (err == error.NotFound) {
            return fido.ctap.authenticator.Callbacks.LoadError.DoesNotExist;
        } else {
            return fido.ctap.authenticator.Callbacks.LoadError.Other;
        }
    };
    return meta;
}

pub fn updateSettings(
    settings: *fido.ctap.authenticator.Meta,
    a: std.mem.Allocator,
) fido.ctap.authenticator.Callbacks.StoreError!void {
    var buffer: [50000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const all = fba.allocator();

    var client = snorlax.Snorlax.init("127.0.0.1", 5984, "admin", "fido", all) catch {
        return fido.ctap.authenticator.Callbacks.LoadError.Other;
    };
    defer client.deinit();

    const x = client.update("passkee", settings, a) catch {
        return fido.ctap.authenticator.Callbacks.StoreError.Other;
    };

    a.free(x.?.id); // we don't need this
    if (settings._rev) |rev| {
        // free old revision id
        a.free(rev);
    }
    settings._rev = x.?.rev;
}

pub fn readCred(
    param: fido.ctap.authenticator.Callbacks.ReadCredParam,
    a: std.mem.Allocator,
) fido.ctap.authenticator.Callbacks.LoadError![]fido.ctap.authenticator.Credential {
    var buffer: [50000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const all = fba.allocator();

    var client = snorlax.Snorlax.init("127.0.0.1", 5984, "admin", "fido", all) catch {
        return fido.ctap.authenticator.Callbacks.LoadError.Other;
    };
    defer client.deinit();

    var arr = std.ArrayList(fido.ctap.authenticator.Credential).init(a);
    errdefer {
        for (arr.items) |item| {
            item.deinit(a);
        }
        arr.deinit();
    }

    switch (param) {
        .id => |id| {
            var meta = client.read(fido.ctap.authenticator.Credential, "passkee", id, a) catch |err| {
                if (err == error.NotFound) {
                    return fido.ctap.authenticator.Callbacks.LoadError.DoesNotExist;
                } else {
                    return fido.ctap.authenticator.Callbacks.LoadError.Other;
                }
            };
            try arr.append(meta);
        },
        .rpId => |id| {
            const X = struct {
                selector: struct {
                    rp_id: struct {
                        @"$eq": []const u8,
                    },
                },
            };
            const x = X{ .selector = .{ .rp_id = .{ .@"$eq" = id } } };

            var creds = client.find("passkee", fido.ctap.authenticator.Credential, x, all) catch |err| {
                if (err == error.NotFound) {
                    return fido.ctap.authenticator.Callbacks.LoadError.DoesNotExist;
                } else {
                    return fido.ctap.authenticator.Callbacks.LoadError.Other;
                }
            };
            defer creds.deinit(all);

            for (creds.docs) |d| {
                try arr.append(try d.copy(a));
            }
        },
        .all => |_| {
            const X = struct {
                selector: struct {
                    discoverable: struct {
                        @"$exists": bool,
                    },
                },
            };
            const x = X{ .selector = .{ .discoverable = .{ .@"$exists" = true } } };

            var creds = client.find("passkee", fido.ctap.authenticator.Credential, x, all) catch |err| {
                if (err == error.NotFound) {
                    return fido.ctap.authenticator.Callbacks.LoadError.DoesNotExist;
                } else {
                    return fido.ctap.authenticator.Callbacks.LoadError.Other;
                }
            };
            defer creds.deinit(all);

            for (creds.docs) |d| {
                try arr.append(try d.copy(a));
            }
        },
    }

    return try arr.toOwnedSlice();
}

pub fn updateCred(
    cred: *fido.ctap.authenticator.Credential,
    a: std.mem.Allocator,
) fido.ctap.authenticator.Callbacks.StoreError!void {
    var buffer: [50000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const all = fba.allocator();

    var client = snorlax.Snorlax.init("127.0.0.1", 5984, "admin", "fido", all) catch {
        return fido.ctap.authenticator.Callbacks.LoadError.Other;
    };
    defer client.deinit();

    const x = client.update("passkee", cred, a) catch {
        return fido.ctap.authenticator.Callbacks.StoreError.Other;
    };

    a.free(x.?.id); // we don't need this
    if (cred._rev) |rev| {
        // free old revision id
        a.free(rev);
    }
    cred._rev = x.?.rev;
}

pub fn deleteCred(
    cred: *fido.ctap.authenticator.Credential,
) fido.ctap.authenticator.Callbacks.LoadError!void {
    var buffer: [50000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const all = fba.allocator();

    var client = snorlax.Snorlax.init("127.0.0.1", 5984, "admin", "fido", all) catch {
        return fido.ctap.authenticator.Callbacks.LoadError.Other;
    };
    defer client.deinit();

    _ = client.delete("passkee", cred._id, cred._rev.?, null) catch |err| {
        if (err == error.NotFound) {
            return fido.ctap.authenticator.Callbacks.LoadError.DoesNotExist;
        } else {
            return fido.ctap.authenticator.Callbacks.LoadError.Other;
        }
    };
}

// +++++++++++++++++++++++++++++++++++++++++++++
// USB HID
// +++++++++++++++++++++++++++++++++++++++++++++

fn create(fd: std.fs.File) !void {
    const device_name = "fido2-device";

    var event = std.mem.zeroes(uhid.uhid_event);
    event.type = uhid.UHID_CREATE2;
    std.mem.copy(u8, event.u.create2.name[0..device_name.len], device_name);
    @memcpy(
        event.u.create2.rd_data[0..hid.ReportDescriptorFidoU2f[0..].len],
        hid.ReportDescriptorFidoU2f[0..],
    );
    event.u.create2.rd_size = hid.ReportDescriptorFidoU2f[0..].len;
    event.u.create2.bus = uhid.BUS_USB;
    event.u.create2.vendor = 0x15d9;
    event.u.create2.product = 0x0a37;
    event.u.create2.version = 0;
    event.u.create2.country = 0;

    try uhid_write(fd, &event);
}

// doesnt work???
fn send_descriptor_string(fd: std.fs.File, s: []const u8) !void {
    var event = std.mem.zeroes(uhid.uhid_event);
    event.type = uhid.UHID_INPUT2;
    event.u.input2.data[0] = 3;
    @memcpy(event.u.input2.data[1 .. s.len + 1], s);
    event.u.input.size = @as(uhid.u_short, @intCast(s.len)) + 1;

    try uhid_write(fd, &event);
}

fn uhid_write(fd: std.fs.File, event: *uhid.uhid_event) !void {
    fd.writeAll(std.mem.asBytes(event)) catch |e| {
        std.log.err("Error writing to uhid: {}\n", .{e});
        return e;
    };
}

fn destroy(fd: std.fs.File) !void {
    var event = std.mem.zeroes(uhid.uhid_event);
    event.type = uhid.UHID_DESTROY;
    return uhid_write(fd, &event);
}
