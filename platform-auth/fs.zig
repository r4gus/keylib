const std = @import("std");
const cbor = @import("zbor");
const cks = @import("cks");
const fido = @import("fido");

var store: ?cks.CKS = null;

pub fn load(path: []const u8, a: std.mem.Allocator, pw: []const u8) !void {
    var dir = std.fs.cwd();

    var file = dir.openFile(path, .{ .mode = .read_write }) catch {
        store = try cks.CKS.new(
            1,
            0,
            .ChaCha20,
            .None,
            .Argon2id,
            "PassKeyZ",
            "DB1",
            a,
            std.crypto.random,
            std.time.milliTimestamp,
        );

        try writeBack(path, pw);

        return;
    };

    const data = try file.readToEndAlloc(a, 64000);
    defer a.free(data);

    store = try cks.CKS.open(
        data,
        pw,
        a,
        std.crypto.random,
        std.time.milliTimestamp,
    );
}

/// This function MOST NOT be called if a `load` has failed!
pub fn get() *cks.CKS {
    return &store.?;
}

pub fn writeBack(path: []const u8, pw: []const u8) !void {
    var dir = std.fs.cwd();

    var file = dir.openFile(path, .{ .mode = .read_write }) catch blk: {
        break :blk try dir.createFile(path, .{});
    };

    try store.?.seal(file.writer(), pw);
}
