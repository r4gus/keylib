const std = @import("std");
const fido = @import("fido");

const fs = @import("fs.zig");
const LoadError = fido.ctap.authenticator.Callbacks.LoadError;
const UpResult = fido.ctap.authenticator.Callbacks.UpResult;

/// Fill the given buffer with (cryptographically secure) random bytes
pub fn rand(b: []u8) void {
    std.crypto.random.bytes(b);
}

/// Get the epoch time in ms
pub fn millis() u64 {
    return @intCast(u64, std.time.milliTimestamp());
}

pub fn up(user: ?*const fido.common.User, rp: ?*const fido.common.RelyingParty) UpResult {
    const stdin = std.io.getStdIn().reader();
    const stdout = std.io.getStdOut().writer();

    if (user) |u| {
        stdout.print("user:\n  id: {s}\n", .{u.id}) catch unreachable;
    }
    if (rp) |_rp| {
        stdout.print("rp:\n  id: {s}\n", .{_rp.id}) catch unreachable;
    }

    var buf: [16]u8 = undefined;

    stdout.print("allow action [Y/n]: ", .{}) catch unreachable;
    if (stdin.readUntilDelimiterOrEof(buf[0..], '\n') catch unreachable) |user_input| {
        if (user_input[0] == 'y' or user_input[0] == 'Y') {
            return .Accepted;
        } else {
            return .Denied;
        }
    } else {
        return .Denied;
    }

    return .Accepted;
}

pub fn reset() void {}

pub fn loadCurrentStoredPIN() LoadError![32]u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();
    var d = fs.Data.load(allocator) catch return LoadError.NotEnoughMemory;
    defer d.deinit(allocator);

    if (d.pin_hash) |ph| {
        return ph;
    } else {
        return LoadError.DoesNotExist;
    }
}

pub fn storeCurrentStoredPIN(pin: [32]u8) void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();
    var d = fs.Data.load(allocator) catch unreachable;
    defer {
        d.writeBack(allocator) catch unreachable;
        d.deinit(allocator);
    }

    d.pin_hash = pin;
    //std.debug.print("new pin hash: {}\n", .{std.fmt.fmtSliceHexUpper(&d.pin_hash.?)});
}

pub fn loadPINCodePointLength() LoadError!u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();
    var d = fs.Data.load(allocator) catch return LoadError.NotEnoughMemory;
    defer d.deinit(allocator);

    if (d.pin_length) |len| {
        return len;
    } else {
        return LoadError.DoesNotExist;
    }
}

pub fn storePINCodePointLength(l: u8) void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();
    var d = fs.Data.load(allocator) catch unreachable;
    defer {
        d.writeBack(allocator) catch unreachable;
        d.deinit(allocator);
    }

    d.pin_length = l;
}

var retries: u8 = 8;

pub fn get_retries() LoadError!u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();
    var d = fs.Data.load(allocator) catch return LoadError.NotEnoughMemory;
    defer d.deinit(allocator);

    return d.retries;
}

pub fn set_retries(r: u8) void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();
    var d = fs.Data.load(allocator) catch unreachable;
    defer {
        d.writeBack(allocator) catch unreachable;
        d.deinit(allocator);
    }

    d.retries = r;
}

pub fn load_credential_by_id(id: []const u8, a: std.mem.Allocator) LoadError![]const u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();
    var d = fs.Data.load(allocator) catch return LoadError.NotEnoughMemory;
    defer d.deinit(allocator);

    std.debug.print("try load credential with id: {x}\n", .{
        std.fmt.fmtSliceHexUpper(id),
    });

    const cred = d.get_cred(id, a);
    if (cred != null) return cred.?;

    std.debug.print("didn't find credential\n", .{});
    return LoadError.DoesNotExist;
}

pub fn store_credential_by_id(id: []const u8, cred: []const u8) void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();
    var d = fs.Data.load(allocator) catch unreachable;
    defer {
        d.writeBack(allocator) catch unreachable;
        d.deinit(allocator);
    }

    //std.debug.print("id: {x}, data: {x}\n", .{
    //    std.fmt.fmtSliceHexUpper(id),
    //    std.fmt.fmtSliceHexUpper(cred),
    //});

    d.set_cred(id, cred, allocator) catch {
        std.debug.print("unable to store credential\n", .{});
    };
}
