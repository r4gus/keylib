const std = @import("std");
const dobj = @import("dobj.zig");

const ErrorCodes = dobj.ErrorCodes;
const commands = @import("commands.zig");
const Commands = commands.Commands;
const getCommand = commands.getCommand;
const authenticator = @import("main.zig");
const Auth = authenticator.Auth;
const User = dobj.User;
const RelyingParty = dobj.RelyingParty;

// {"master_secret": h'e47a9b6ffeba6e96de8306454748d77dc08b2e47c99ce4896a262b710095f46b', "pin_hash": h'48d5ad47b3406da2b35f556c62718c66', "pin_length": 10, "sign_ctr": 0}
// Hkdf.extract(cdb1a61bc0547a3e4ca761884aad3d9ffd1db1167771f322511c5a42162c27c0, candystick) = d8abc5124b4fbab7c5957dab1246a9bab0a78e99933f36f7530b9664a9f7a5f3
// {"meta": {"valid": 0xf1, "salt": h'cdb1a61bc0547a3e4ca761884aad3d9ffd1db1167771f322511c5a42162c27c0', "nonce_ctr": h'000000000000000000000000', "pin_retries": 8}, "c": h'35a07a14a4c5b5b6f56f9d9104e35ddeeb2dedabea651963d34d38da7926240bba47e88512f4548367db2dcfb66953f651618cf46f645b72b1c3a58369ca9ba32819859380157ebfdea5c7bd15dc09c0a3bbfeb6e3cfe41cba4c74060c779feffb', "tag": h'e67740ccacf37310b0d596eb67dec1c5'}

const test_data_1 = "\xa3\x64\x6d\x65\x74\x61\xa4\x65\x76\x61\x6c\x69\x64\x18\xf1\x64\x73\x61\x6c\x74\x58\x20\xcd\xb1\xa6\x1b\xc0\x54\x7a\x3e\x4c\xa7\x61\x88\x4a\xad\x3d\x9f\xfd\x1d\xb1\x16\x77\x71\xf3\x22\x51\x1c\x5a\x42\x16\x2c\x27\xc0\x69\x6e\x6f\x6e\x63\x65\x5f\x63\x74\x72\x4c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x6b\x70\x69\x6e\x5f\x72\x65\x74\x72\x69\x65\x73\x08\x61\x63\x58\x61\x35\xa0\x7a\x14\xa4\xc5\xb5\xb6\xf5\x6f\x9d\x91\x04\xe3\x5d\xde\xeb\x2d\xed\xab\xea\x65\x19\x63\xd3\x4d\x38\xda\x79\x26\x24\x0b\xba\x47\xe8\x85\x12\xf4\x54\x83\x67\xdb\x2d\xcf\xb6\x69\x53\xf6\x51\x61\x8c\xf4\x6f\x64\x5b\x72\xb1\xc3\xa5\x83\x69\xca\x9b\xa3\x28\x19\x85\x93\x80\x15\x7e\xbf\xde\xa5\xc7\xbd\x15\xdc\x09\xc0\xa3\xbb\xfe\xb6\xe3\xcf\xe4\x1c\xba\x4c\x74\x06\x0c\x77\x9f\xef\xfb\x63\x74\x61\x67\x50\xe6\x77\x40\xcc\xac\xf3\x73\x10\xb0\xd5\x96\xeb\x67\xde\xc1\xc5";

// Just for tests
const test_impl = struct {
    var d: [512]u8 = undefined;
    var data: []const u8 = test_data_1;

    pub fn requestPermission(user: ?*const User, rp: ?*const RelyingParty) bool {
        _ = user;
        _ = rp;
        return true;
    }

    pub fn rand() u32 {
        const S = struct {
            var i: u32 = 0;
        };

        S.i += 1;

        return S.i;
    }

    pub fn load(allocator: std.mem.Allocator) []const u8 {
        var x = allocator.alloc(u8, data.len) catch unreachable; // we always provide enough memory
        std.mem.copy(u8, x[0..data.len], data[0..]);
        return x;
    }

    pub fn store(out: []const u8) void {
        std.mem.copy(u8, d[0..out.len], out[0..]);
        data = d[0..out.len];
    }

    pub fn millis() u32 {
        return @intCast(u32, std.time.milliTimestamp());
    }
};

test "fetch command from data" {
    try std.testing.expectError(ErrorCodes.invalid_length, getCommand(""));
    try std.testing.expectEqual(Commands.authenticator_make_credential, try getCommand("\x01"));
    try std.testing.expectEqual(Commands.authenticator_get_assertion, try getCommand("\x02"));
    try std.testing.expectEqual(Commands.authenticator_get_info, try getCommand("\x04"));
    try std.testing.expectEqual(Commands.authenticator_client_pin, try getCommand("\x06"));
    try std.testing.expectEqual(Commands.authenticator_reset, try getCommand("\x07"));
    try std.testing.expectEqual(Commands.authenticator_get_next_assertion, try getCommand("\x08"));
    try std.testing.expectEqual(Commands.authenticator_vendor_first, try getCommand("\x40"));
    try std.testing.expectEqual(Commands.authenticator_vendor_last, try getCommand("\xbf"));
    try std.testing.expectError(ErrorCodes.invalid_command, getCommand("\x03"));
    try std.testing.expectError(ErrorCodes.invalid_command, getCommand("\x09"));
}

test "version enum to string" {
    try std.testing.expectEqualStrings("FIDO_2_0", dobj.Versions.FIDO_2_0.toString());
    try std.testing.expectEqualStrings("U2F_V2", dobj.Versions.U2F_V2.toString());
}

test "default Authenticator initialization" {
    const a = Auth(test_impl);
    const auth = a.initDefault([_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });

    try std.testing.expectEqual(dobj.Versions.FIDO_2_0, auth.info.@"1"[0]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, &auth.info.@"3");
    try std.testing.expectEqual(false, auth.info.@"4".?.plat);
    try std.testing.expectEqual(false, auth.info.@"4".?.rk);
    try std.testing.expectEqual(auth.info.@"4".?.clientPin, null);
    try std.testing.expectEqual(true, auth.info.@"4".?.up);
    try std.testing.expectEqual(auth.info.@"4".?.uv, null);
    try std.testing.expectEqual(auth.info.@"5", null);
    try std.testing.expectEqual(auth.info.@"6", null);
}

test "authenticator get info" {
    const allocator = std.testing.allocator;

    const a = Auth(test_impl);
    const auth = a.initDefault([_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });
    
    const x = try auth.handle(allocator, "\x04");
    defer allocator.free(x);
}