const std = @import("std");
const allocator = std.heap.c_allocator;

const keylib = @import("keylib");
const Auth = keylib.ctap.authenticator.Auth;

const cb = keylib.ctap.authenticator.callbacks;
pub const Error = cb.Error;
pub const UpResult = cb.UpResult;
pub const Callbacks = cb.Callbacks;

const CtapHid = keylib.ctap.transports.ctaphid.authenticator.CtapHid;
const CtapHidMessageIterator = keylib.ctap.transports.ctaphid.authenticator.CtapHidMessageIterator;
const CtapHidMsg = keylib.ctap.transports.ctaphid.authenticator.CtapHidMsg;

pub const AuthSettings = extern struct {
    aaguid: [16]u8 = "\x6f\x15\x82\x74\xaa\xb6\x44\x3d\x9b\xcf\x8a\x3f\x69\x29\x7c\x88".*,
};

export fn auth_init(callbacks: Callbacks, settings: AuthSettings) ?*anyopaque {
    var a = allocator.create(Auth) catch {
        return null;
    };

    a.* = keylib.ctap.authenticator.Auth{
        // The callbacks are the interface between the authenticator and the rest of the application (see below).
        .callbacks = callbacks,
        // The commands map from a command code to a command function. All functions have the
        // same interface and you can implement your own to extend the authenticator beyond
        // the official spec, e.g. add a command to store passwords.
        .commands = &.{
            .{ .cmd = 0x01, .cb = keylib.ctap.commands.authenticator.authenticatorMakeCredential },
            .{ .cmd = 0x02, .cb = keylib.ctap.commands.authenticator.authenticatorGetAssertion },
            .{ .cmd = 0x04, .cb = keylib.ctap.commands.authenticator.authenticatorGetInfo },
            .{ .cmd = 0x06, .cb = keylib.ctap.commands.authenticator.authenticatorClientPin },
            .{ .cmd = 0x0b, .cb = keylib.ctap.commands.authenticator.authenticatorSelection },
        },
        // The settings are returned by a getInfo request and describe the capabilities
        // of your authenticator. Make sure your configuration is valid based on the
        // CTAP2 spec!
        .settings = .{
            // Those are the FIDO2 spec you support
            .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
            // The extensions are defined as strings which should make it easy to extend
            // the authenticator (in combination with a new command).
            .extensions = &.{"credProtect"},
            // This should be unique for all models of the same authenticator.
            .aaguid = settings.aaguid,
            .options = .{
                // We don't support the credential management command. If you want to
                // then you need to implement it yourself and add it to commands and
                // set this flag to true.
                .credMgmt = false,
                // We support discoverable credentials, a.k.a resident keys, a.k.a passkeys
                .rk = true,
                // We support built in user verification (see the callback below)
                .uv = true,
                // This is a platform authenticator even if we use usb for ipc
                .plat = true,
                // We don't support client pin but you could also add the command
                // yourself and set this to false (not initialized) or true (initialized).
                .clientPin = null,
                // We support pinUvAuthToken
                .pinUvAuthToken = true,
                // If you want to enforce alwaysUv you also have to set this to true.
                .alwaysUv = false,
            },
            // The pinUvAuth protocol to support. This library implements V1 and V2.
            .pinUvAuthProtocols = &.{.V2},
            // The transports your authenticator supports.
            .transports = &.{.usb},
            // The algorithms you support.
            .algorithms = &.{.{ .alg = .Es256 }},
            .firmwareVersion = 0xcafe,
            .remainingDiscoverableCredentials = 100,
        },
        // Here we initialize the pinUvAuth token data structure wich handles the generation
        // and management of pinUvAuthTokens.
        .token = keylib.ctap.pinuv.PinUvAuth.v2(std.crypto.random),
        // Here we set the supported algorithm. You can also implement your
        // own and add them here.
        .algorithms = &.{
            keylib.ctap.crypto.algorithms.Es256,
        },
        // This allocator is used to allocate memory and has to be the same
        // used for the callbacks.
        .allocator = allocator,
        // A function to get the epoch time as i64.
        .milliTimestamp = std.time.milliTimestamp,
        // A cryptographically secure random number generator
        .random = std.crypto.random,
        // If you don't want to increment the sign counts
        // of credentials (e.g. because you sync them between devices)
        // set this to true.
        .constSignCount = true,
    };
    a.init() catch {
        return null;
    };

    return @as(*anyopaque, @ptrCast(a));
}

export fn auth_deinit(a: *anyopaque) void {
    const auth = @as(*Auth, @ptrCast(@alignCast(a)));
    auth.allocator.destroy(auth);
}

export fn auth_handle(
    a: *anyopaque,
    m: ?*anyopaque,
) void {
    if (m == null) return;

    const auth = @as(*Auth, @ptrCast(@alignCast(a)));
    const msg = @as(*CtapHidMsg, @ptrCast(@alignCast(m.?)));

    switch (msg.cmd) {
        .cbor => {
            var out: [7609]u8 = undefined; // TODO: we have to make this configurable
            const r = auth.handle(&out, msg.getData());
            @memcpy(msg._data[0..r.len], r);
            msg.len = r.len;
        },
        else => {},
    }
}

export fn ctaphid_init() ?*anyopaque {
    const c = allocator.create(CtapHid) catch {
        return null;
    };

    c.* = CtapHid.init(allocator, std.crypto.random);

    return @as(*anyopaque, @ptrCast(c));
}

export fn ctaphid_deinit(a: *anyopaque) void {
    const c = @as(*CtapHid, @ptrCast(@alignCast(a)));
    c.deinit();
    allocator.destroy(c);
}

/// This function either returns null or a pointer to a CtapHidMsg.
export fn ctaphid_handle(
    ctap: *anyopaque,
    packet: [*c]const u8,
    len: usize,
) ?*anyopaque {
    const ctaphid = @as(*CtapHid, @ptrCast(@alignCast(ctap)));

    if (ctaphid.handle(packet[0..len])) |res| {
        const msg = allocator.create(CtapHidMsg) catch {
            return null;
        };
        msg.* = res;
        return @as(*anyopaque, @ptrCast(msg));
    } else {
        return null;
    }
}

export fn ctaphid_iterator(m: *anyopaque) ?*anyopaque {
    const msg = @as(*CtapHidMsg, @ptrCast(@alignCast(m)));
    const iter = allocator.create(CtapHidMessageIterator) catch {
        return null;
    };

    iter.* = msg.iterator();
    return @as(*anyopaque, @ptrCast(iter));
}

export fn ctaphid_iterator_next(iter: *anyopaque, out: [*c]u8) c_int {
    const iterator = @as(*CtapHidMessageIterator, @ptrCast(@alignCast(iter)));

    if (iterator.next()) |packet| {
        @memcpy(out[0..packet.len], packet); // 64 bytes
        return 1;
    } else {
        return 0;
    }
}

export fn ctaphid_iterator_deinit(iter: *anyopaque) void {
    const iterator = @as(*CtapHidMessageIterator, @ptrCast(@alignCast(iter)));
    iterator.deinit();
    allocator.destroy(iterator);
}
