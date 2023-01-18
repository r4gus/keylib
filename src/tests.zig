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

const test_data_1 = "\xF1\x11\x25\xdc\xed\x00\x72\x95\xa2\x98\x63\x68\x2d\x7b\x1c\xc3\x83\x58\x38\xcf\x7a\x19\x62\xe0\x90\x5a\x36\xb2\xed\xa6\x07\x3e\xe1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00";
const test_data_2 = "\x00\x11\x25\xdc\xed\x00\x72\x95\xa2\x98\x63\x68\x2d\x7b\x1c\xc3\x83\x58\x38\xcf\x7a\x19\x62\xe0\x90\x5a\x36\xb2\xed\xa6\x07\x3e\xe1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00";

// Just for tests
const test_impl = struct {
    var d: [authenticator.data_len]u8 = test_data_1.*;

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

    pub fn load() [authenticator.data_len]u8 {
        // VALID || MS || PIN || CTR || RETRIES
        return d;
    }

    pub fn store(data: [authenticator.data_len]u8) void {
        d = data;
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
    const auth = a.initDefault(&[_]dobj.Versions{.FIDO_2_0}, [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });

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

test "get info from 'default' authenticator" {
    const allocator = std.testing.allocator;

    const a = Auth(test_impl);
    const auth = a.initDefault(&[_]dobj.Versions{.FIDO_2_0}, [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });

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

test "getting retries from authenticator" {
    // Retries count is the number of attempts remaining before lockout.
    // When the device is nearing authenticator lockout, the platform
    // can optionally warn the user to be careful while entering the PIN.
    const allocator = std.testing.allocator;

    const req = "\x06\xA2\x01\x01\x02\x01";

    const a = Auth(test_impl);
    const auth = a.initDefault(&[_]dobj.Versions{.FIDO_2_0}, [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });

    const response = try auth.handle(allocator, req);
    defer allocator.free(response);

    try std.testing.expectEqualStrings("\x00\xA1\x03\x08", response);
}

test "getting shared secret from authenticator" {}

test "testing data getters" {
    test_impl.d = test_data_1.*; // reset test data
    const a = Auth(test_impl);

    var x = a.Data.load();

    try std.testing.expectEqual(true, x.isValid());
    try std.testing.expectEqualSlices(u8, "\x11\x25\xdc\xed\x00\x72\x95\xa2\x98\x63\x68\x2d\x7b\x1c\xc3\x83\x58\x38\xcf\x7a\x19\x62\xe0\x90\x5a\x36\xb2\xed\xa6\x07\x3e\xe1", &x.getMs());
    try std.testing.expectEqual(false, x.isPinSet());
    try std.testing.expectEqual(@intCast(u8, 8), x.getRetries());

    // Sign counter will automatically increase
    try std.testing.expectEqual(@intCast(u32, 0), x.getSignCtr());
    try std.testing.expectEqual(@intCast(u32, 1), x.getSignCtr());
    try std.testing.expectEqual(@intCast(u32, 2), x.getSignCtr());
}

test "testing data setters" {
    test_impl.d = test_data_2.*; // reset test data
    const a = Auth(test_impl);

    var x = a.Data.load();

    try std.testing.expectEqual(false, x.isValid());
    x.setValid();
    try std.testing.expectEqual(true, x.isValid());

    try std.testing.expectEqual(@intCast(u8, 8), x.getRetries());
    x.setRetries(7);
    try std.testing.expectEqual(@intCast(u8, 7), x.getRetries());

    try std.testing.expectEqualSlices(u8, "\x11\x25\xdc\xed\x00\x72\x95\xa2\x98\x63\x68\x2d\x7b\x1c\xc3\x83\x58\x38\xcf\x7a\x19\x62\xe0\x90\x5a\x36\xb2\xed\xa6\x07\x3e\xe1", &x.getMs());
    x.setMs("\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00".*);
    try std.testing.expectEqualSlices(u8, "\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00", &x.getMs());
}
