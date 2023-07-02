const std = @import("std");
const fido = @import("fido");
const cks = @import("cks");

const fs = @import("fs.zig");
const LoadError = fido.ctap.authenticator.Callbacks.LoadError;
const UpResult = fido.ctap.authenticator.Callbacks.UpResult;

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

pub fn getEntry(id: []const u8) ?*cks.Entry {
    var store = fs.get();
    return store.getEntry(id);
}

pub fn addEntry(entry: cks.Entry) cks.Error!void {
    var store = fs.get();
    try store.addEntry(entry);
}

pub fn persist() error{Fatal}!void {
    const pw = if (password(null)) |pw| pw else return error.Fatal;
    fs.writeBack(pw) catch {
        return error.Fatal;
    };
}
