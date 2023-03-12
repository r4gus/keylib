const std = @import("std");
const data = @import("data.zig");
const Resources = @import("Resources.zig");
const Authenticator = @import("Authenticator.zig");

fn rand(b: []u8) void {
    const S = struct {
        var i: u8 = 0;
    };

    var j: usize = 0;
    while (j < b.len) : (j += 1) {
        b[j] = S.i;
        S.i += 1;
    }
}

pub fn load(allocator: std.mem.Allocator) []u8 {
    var x = allocator.alloc(u8, 0) catch unreachable;
    return x;
}

pub fn store(out: []const u8) void {
    _ = out;
}

pub fn millis() u32 {
    return @intCast(u32, std.time.milliTimestamp());
}

pub fn request_permission(user: ?*const data.User, rp: ?*const data.RelyingParty) bool {
    _ = user;
    _ = rp;
    return true;
}

test "get a new authenticator instance" {
    const resources = Resources{
        .rand = rand,
        .millis = millis,
        .load = load,
        .store = store,
        .request_permission = request_permission,
    };

    const auth = Authenticator.new_default(
        [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        resources,
    );

    try std.testing.expectEqual(data.Versions.FIDO_2_1, auth.settings.versions[0]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, &auth.settings.aaguid);
    try std.testing.expectEqual(false, auth.settings.options.?.plat);
    try std.testing.expectEqual(false, auth.settings.options.?.rk);
    try std.testing.expectEqual(true, auth.settings.options.?.up);
    try std.testing.expectEqual(true, auth.settings.options.?.clientPin.?);
    try std.testing.expectEqual(true, auth.settings.options.?.pinUvAuthToken.?);
    try std.testing.expectEqual(auth.settings.options.?.uv, null);
}
