const std = @import("std");
const allocator = std.heap.c_allocator;

const fido = @import("keylib");
const Auth = fido.ctap.authenticator.Auth;

const cb = fido.ctap.authenticator.callbacks;
pub const Error = cb.Error;
pub const UpResult = cb.UpResult;
pub const Callbacks = cb.Callbacks;

const CtapHid = fido.ctap.transports.ctaphid.authenticator.CtapHid;
const CtapHidMessageIterator = fido.ctap.transports.ctaphid.authenticator.CtapHidMessageIterator;

export fn auth_init(callbacks: Callbacks) ?*anyopaque {
    var a = allocator.create(Auth) catch {
        return null;
    };

    a.* = Auth.default(callbacks, allocator);
    a.init() catch {};

    return @as(*anyopaque, @ptrCast(a));
}

export fn auth_deinit(a: *anyopaque) void {
    const auth = @as(*Auth, @ptrCast(@alignCast(a)));
    auth.allocator.destroy(auth);
}

export fn ctaphid_init() ?*anyopaque {
    var c = allocator.create(CtapHid) catch {
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

export fn ctaphid_handle(
    ctap: *anyopaque,
    packet: [*c]const u8,
    len: usize,
    auth: *anyopaque,
) ?*anyopaque {
    const authenticator = @as(*Auth, @ptrCast(@alignCast(auth)));
    const ctaphid = @as(*CtapHid, @ptrCast(@alignCast(ctap)));

    if (ctaphid.handle(packet[0..len], authenticator)) |res| {
        var iter = allocator.create(CtapHidMessageIterator) catch {
            return null;
        };
        iter.* = res;
        return @as(*anyopaque, @ptrCast(iter));
    } else {
        return null;
    }
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
