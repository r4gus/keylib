const std = @import("std");
const cks = @import("cks");
const fido = @import("fido");
const hid = @import("hid.zig");

const notify = @cImport({
    @cInclude("libnotify/notify.h");
});

const uhid = @cImport(
    @cInclude("linux/uhid.h"),
);

pub var loop: ?*notify.GMainLoop = null;

var store: ?cks.CKS = null;

var device: std.fs.File = undefined;

var authenticator: fido.ctap.authenticator.Authenticator = undefined;

var uv: ?bool = null;

var notification: [*c]notify.NotifyNotification = undefined;

//const la = std.heap.LoggingAllocator(.debug, .debug);
//var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//var lagpa = la.init(gpa.allocator());
//var allocator = lagpa.allocator();

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

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
        std.log.err("unable to read from device", .{});
        return 0;
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
    loop = notify.g_main_loop_new(null, 0);

    const interval_ms: notify.guint = 10;
    var source = notify.g_timeout_source_new(interval_ms);
    notify.g_source_set_callback(source, &packet_callback, null, null);
    _ = notify.g_source_attach(source, null);

    _ = notify.notify_init("Hello world!");
    defer notify.notify_uninit();

    // ------------------- Load db ----------------------------
    const pw = password("password");

    store = load_key_store(allocator, pw.?) catch {
        std.log.err("error: unable to open key store\n", .{});
        return;
    };
    // --------------------------------------------------------

    // ------------------- Setup USB HID ----------------------
    const path = "/dev/uhid";
    device = std.fs.openFileAbsolute(path, .{ .mode = .read_write }) catch {
        std.log.err("Can't open uhid-cdev {s}\n", .{path});
        return;
    };
    defer device.close();

    try create(device);
    defer destroy(device) catch unreachable;
    // --------------------------------------------------------

    // ------------------- Initialize authenticator -----------
    authenticator = fido.ctap.authenticator.Authenticator{
        .settings = .{
            .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
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
            .createEntry = createEntry,
            .getEntry = getEntry,
            .getEntries = getEntries,
            .addEntry = addEntry,
            .removeEntry = removeEntry,
            .persist = persist,
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

    if (authenticator.token.one) |*one| {
        one.initialize();
    }
    if (authenticator.token.two) |*two| {
        two.initialize();
    }

    try authenticator.init();
    // --------------------------------------------------------

    notify.g_main_loop_run(loop);
}

// +++++++++++++++++++++++++++++++++++++++++++++
// Store
// +++++++++++++++++++++++++++++++++++++++++++++

const CONFIG_DIR_NAME = ".passkee";

fn load_key_store(a: std.mem.Allocator, pw: []const u8) !cks.CKS {
    // Get path to the users home folder
    const home = try getHome(a);
    defer a.free(home);

    // Open the passkee config folder
    var config_path = try a.alloc(u8, home.len + CONFIG_DIR_NAME.len + 1);
    @memcpy(config_path[0..home.len], home);
    config_path[home.len] = '/';
    @memcpy(config_path[home.len + 1 ..], CONFIG_DIR_NAME);
    defer a.free(config_path);

    var config_dir = try openConfigFolder(config_path);

    // Try to load database file
    createFile(config_dir, "secrets.cks", pw, a) catch {}; // always try to create db
    const data = try loadFile(config_dir, "secrets.cks", a);

    return try cks.CKS.open(
        data,
        pw,
        a,
        std.crypto.random,
        std.time.milliTimestamp,
    );
}

pub fn saveKeyStore(a: std.mem.Allocator, pw: []const u8) !void {
    // Get path to the users home folder
    const home = try getHome(a);
    defer a.free(home);

    // Open the passkee config folder
    var config_path = try a.alloc(u8, home.len + CONFIG_DIR_NAME.len + 1);
    @memcpy(config_path[0..home.len], home);
    config_path[home.len] = '/';
    @memcpy(config_path[home.len + 1 ..], CONFIG_DIR_NAME);
    defer a.free(config_path);

    var config_dir = try openConfigFolder(config_path);

    // Store key store
    try writeFile(config_dir, "secrets.cks", &store.?, pw);
}

fn getHome(a: std.mem.Allocator) ![]const u8 {
    if (std.os.getenv("HOME")) |home| {
        var d = try a.alloc(u8, home.len);
        @memcpy(d, home);
        return d;
    } else {
        return error.NotFound;
    }
}

pub fn openConfigFolder(path: []const u8) !std.fs.Dir {
    return std.fs.openDirAbsolute(path, .{}) catch {
        std.log.warn("Directory {s} doesn't exist. Try to create it...", .{path});
        try std.fs.makeDirAbsolute(path);
        return try std.fs.openDirAbsolute(path, .{});
    };
}

pub fn loadFile(dir: std.fs.Dir, path: []const u8, a: std.mem.Allocator) ![]const u8 {
    var file = try dir.openFile(path, .{ .mode = .read_write });
    return try file.readToEndAlloc(a, 128000);
}

pub fn createFile(dir: std.fs.Dir, name: []const u8, pw: []const u8, a: std.mem.Allocator) !void {
    // Test if file already exists
    dir.access(name, .{ .mode = .read_write }) catch {
        var o = try cks.CKS.new(
            1,
            0,
            .ChaCha20,
            .None,
            .Argon2id,
            "PassKee",
            "PassKee-Secrets",
            a,
            std.crypto.random,
            std.time.milliTimestamp,
        );
        defer o.deinit();

        try writeFile(dir, name, &o, pw);
        return;
    };
    return error.FileAlreadyExists;
}

pub fn writeFile(dir: std.fs.Dir, path: []const u8, s: *cks.CKS, pw: []const u8) !void {
    var file = dir.openFile(path, .{ .mode = .read_write }) catch blk: {
        break :blk try dir.createFile(path, .{});
    };

    try file.setEndPos(0);
    try s.seal(file.writer(), pw);
}

/// This function MOST NOT be called if a `load` has failed!
pub fn get() *cks.CKS {
    return &store.?;
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

pub fn createEntry(id: []const u8) cks.Error!cks.Entry {
    return try store.?.createEntry(id);
}

pub fn getEntry(id: []const u8) ?*cks.Entry {
    return store.?.getEntry(id);
}

pub fn getEntries() ?[]cks.Entry { // TODO: maybe rename to getResidentKeys
    return if (store.?.data.entries) |entries| entries[1..] else null; // first entry is "Settings"
}

pub fn addEntry(entry: cks.Entry) cks.Error!void {
    try store.?.addEntry(entry);
}

pub fn removeEntry(id: []const u8) cks.Error!void {
    try store.?.removeEntry(id);
}

pub fn persist() error{Fatal}!void {
    const pw = if (password(null)) |pw| pw else return error.Fatal;
    saveKeyStore(allocator, pw) catch {
        return error.Fatal;
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
