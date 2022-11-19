const std = @import("std");

const ErrorCodes = @import("error.zig").ErrorCodes;
const commands = @import("commands.zig");
const Commands = commands.Commands;
const getCommand = commands.getCommand;
const Versions = @import("version.zig").Versions;
const authenticator = @import("main.zig");
const Auth = authenticator.Auth;

// Just for tests
const test_impl = struct {
    pub fn rand() u32 {
        const S = struct {
            var i: u32 = 0;
        };

        S.i += 1;

        return S.i;
    }

    pub fn getMs() [authenticator.ms_length]u8 {
        return .{ 0x11, 0x25, 0xdc, 0xed, 0x00, 0x72, 0x95, 0xa2, 0x98, 0x63, 0x68, 0x2d, 0x7b, 0x1c, 0xc3, 0x83, 0x58, 0x38, 0xcf, 0x7a, 0x19, 0x62, 0xe0, 0x90, 0x5a, 0x36, 0xb2, 0xed, 0xa6, 0x07, 0x3e, 0xe1 };
    }

    pub fn createMs() void {}
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
    try std.testing.expectEqualStrings("FIDO_2_0", Versions.FIDO_2_0.toString());
    try std.testing.expectEqualStrings("U2F_V2", Versions.U2F_V2.toString());
}

test "default Authenticator initialization" {
    const a = Auth(test_impl);
    const auth = a.initDefault(&[_]Versions{.FIDO_2_0}, [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });

    try std.testing.expectEqual(Versions.FIDO_2_0, auth.@"1_t"[0]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }, &auth.@"3_b");
    try std.testing.expectEqual(false, auth.@"4".?.plat);
    try std.testing.expectEqual(false, auth.@"4".?.rk);
    try std.testing.expectEqual(auth.@"4".?.clientPin, null);
    try std.testing.expectEqual(true, auth.@"4".?.up);
    try std.testing.expectEqual(auth.@"4".?.uv, null);
    try std.testing.expectEqual(auth.@"5", null);
    try std.testing.expectEqual(auth.@"6", null);
}

test "get info from 'default' authenticator" {
    const allocator = std.testing.allocator;

    const a = Auth(test_impl);
    const auth = a.initDefault(&[_]Versions{.FIDO_2_0}, [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });

    const response = try auth.handle(allocator, "\x04");
    defer allocator.free(response);

    try std.testing.expectEqualStrings("\x00\xa3\x01\x81\x68\x46\x49\x44\x4f\x5f\x32\x5f\x30\x03\x50\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x04\xa3\x62\x72\x6b\xf4\x62\x75\x70\xf5\x64\x70\x6c\x61\x74\xf4", response);
}

test "authenticatorMakeCredential (0x01)" {
    // {
    //   1: h'C03991AC3DFF02BA1E520FC59B2D34774A641A4C425ABD313D931061FFBD1A5C',
    //   2: {"id": "localhost", "name": "sweet home localhost"},
    //   3: {
    //     "id": h'781C7860AD88D26332622AF1745DEDB2E7A42B44892939C5566401270DBBC449',
    //     "name": "john smith",
    //     "displayName": "jsmith"
    //   },
    //   4: [{"alg": -7, "type": "public-key"}]
    // }
    const input = "\xa4\x01\x58\x20\xc0\x39\x91\xac\x3d\xff\x02\xba\x1e\x52\x0f\xc5\x9b\x2d\x34\x77\x4a\x64\x1a\x4c\x42\x5a\xbd\x31\x3d\x93\x10\x61\xff\xbd\x1a\x5c\x02\xa2\x62\x69\x64\x69\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x64\x6e\x61\x6d\x65\x74\x73\x77\x65\x65\x74\x20\x68\x6f\x6d\x65\x20\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x03\xa3\x62\x69\x64\x58\x20\x78\x1c\x78\x60\xad\x88\xd2\x63\x32\x62\x2a\xf1\x74\x5d\xed\xb2\xe7\xa4\x2b\x44\x89\x29\x39\xc5\x56\x64\x01\x27\x0d\xbb\xc4\x49\x64\x6e\x61\x6d\x65\x6a\x6a\x6f\x68\x6e\x20\x73\x6d\x69\x74\x68\x6b\x64\x69\x73\x70\x6c\x61\x79\x4e\x61\x6d\x65\x66\x6a\x73\x6d\x69\x74\x68\x04\x81\xa2\x63\x61\x6c\x67\x26\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79";
    _ = input;
}

test "test random function call" {
    const a = Auth(test_impl);

    const x = a.crypto.rand();
    try std.testing.expectEqual(x + 1, a.crypto.rand());
    try std.testing.expectEqual(x + 2, a.crypto.rand());
}

test "key pair generation" {
    const a = Auth(test_impl);
    const kc = try a.crypto.createKeyPair();

    //std.log.err("{any}\n", .{kc.key_pair.public_key.toUncompressedSec1()});

    const kp = try a.crypto.deriveKeyPair(kc.ctx);

    try std.testing.expectEqual(kc.key_pair.public_key.p, kp.public_key.p);
    try std.testing.expectEqual(kc.key_pair.secret_key.bytes, kp.secret_key.bytes);
}
