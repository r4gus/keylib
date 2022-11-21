const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const core = @import("core.zig");
const CborError = core.CborError;
const Pair = core.Pair;
const Tag = core.Tag;
const FloatTag = core.FloatTag;
const Float = core.Float;
const SimpleValue = core.SimpleValue;
const DataItemTag = core.DataItemTag;
const DataItem = core.DataItem;

const encode = @import("encoder.zig").encode;
const encodeAlloc = @import("encoder.zig").encodeAlloc;
const decode = @import("decoder.zig").decode;

const TestError = CborError || error{ TestExpectedEqual, TestUnexpectedResult };

fn test_data_item(data: []const u8, expected: DataItem) TestError!void {
    const allocator = std.testing.allocator;
    const dip = try decode(allocator, data);
    defer dip.deinit(allocator);
    try std.testing.expectEqual(expected, dip);
}

fn test_data_item_eql(data: []const u8, expected: *const DataItem) TestError!void {
    const allocator = std.testing.allocator;
    const dip = try decode(allocator, data);
    defer dip.deinit(allocator);
    try std.testing.expect(expected.*.equal(&dip));
}

test "DataItem.equal test" {
    const di1 = DataItem{ .int = 10 };
    const di2 = DataItem{ .int = 23 };
    const di3 = DataItem{ .int = 23 };
    const di4 = DataItem{ .int = -9988776655 };

    try std.testing.expect(!di1.equal(&di2));
    try std.testing.expect(di2.equal(&di3));
    try std.testing.expect(!di1.equal(&di4));
    try std.testing.expect(!di2.equal(&di4));
    try std.testing.expect(!di3.equal(&di4));

    var allocator = std.testing.allocator;

    var di5 = try DataItem.bytes(&.{10}, .{ .allocator = allocator });
    defer di5.deinit(allocator);

    try std.testing.expect(!di5.equal(&di1));
    try std.testing.expect(!di1.equal(&di5));
    try std.testing.expect(di5.equal(&di5));

    var di6 = try DataItem.bytes(&.{10}, .{ .allocator = allocator });
    defer di6.deinit(allocator);

    try std.testing.expect(di5.equal(&di6));
}

test "MT0: decode cbor unsigned integer value" {
    try test_data_item(&.{0x00}, DataItem{ .int = 0 });
    try test_data_item(&.{0x01}, DataItem{ .int = 1 });
    try test_data_item(&.{0x0a}, DataItem{ .int = 10 });
    try test_data_item(&.{0x17}, DataItem{ .int = 23 });
    try test_data_item(&.{ 0x18, 0x18 }, DataItem{ .int = 24 });
    try test_data_item(&.{ 0x18, 0x19 }, DataItem{ .int = 25 });
    try test_data_item(&.{ 0x18, 0x64 }, DataItem{ .int = 100 });
    try test_data_item(&.{ 0x18, 0x7b }, DataItem{ .int = 123 });
    try test_data_item(&.{ 0x19, 0x03, 0xe8 }, DataItem{ .int = 1000 });
    try test_data_item(&.{ 0x19, 0x04, 0xd2 }, DataItem{ .int = 1234 });
    try test_data_item(&.{ 0x1a, 0x00, 0x01, 0xe2, 0x40 }, DataItem{ .int = 123456 });
    try test_data_item(&.{ 0x1a, 0x00, 0x0f, 0x42, 0x40 }, DataItem{ .int = 1000000 });
    try test_data_item(&.{ 0x1b, 0x00, 0x00, 0x00, 0x02, 0xdf, 0xdc, 0x1c, 0x34 }, DataItem{ .int = 12345678900 });
    try test_data_item(&.{ 0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00 }, DataItem{ .int = 1000000000000 });
    try test_data_item(&.{ 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, DataItem{ .int = 18446744073709551615 });
}

test "MT1: decode cbor signed integer value" {
    try test_data_item(&.{0x20}, DataItem{ .int = -1 });
    try test_data_item(&.{0x22}, DataItem{ .int = -3 });
    try test_data_item(&.{ 0x38, 0x63 }, DataItem{ .int = -100 });
    try test_data_item(&.{ 0x39, 0x01, 0xf3 }, DataItem{ .int = -500 });
    try test_data_item(&.{ 0x39, 0x03, 0xe7 }, DataItem{ .int = -1000 });
    try test_data_item(&.{ 0x3a, 0x00, 0x0f, 0x3d, 0xdc }, DataItem{ .int = -998877 });
    try test_data_item(&.{ 0x3b, 0x00, 0x00, 0x00, 0x02, 0x53, 0x60, 0xa2, 0xce }, DataItem{ .int = -9988776655 });
    try test_data_item(&.{ 0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, DataItem{ .int = -18446744073709551616 });
}

test "MT2: decode cbor byte string" {
    const allocator = std.testing.allocator;

    try test_data_item_eql(&.{0b01000000}, &DataItem{ .bytes = &.{} });

    var di1 = try DataItem.bytes(&.{10}, .{ .allocator = allocator });
    defer di1.deinit(allocator);
    try test_data_item_eql(&.{ 0b01000001, 0x0a }, &di1);

    var di2 = try DataItem.bytes(&.{ 10, 11, 12, 13, 14 }, .{ .allocator = allocator });
    defer di2.deinit(allocator);
    try test_data_item_eql(&.{ 0b01000101, 0x0a, 0xb, 0xc, 0xd, 0xe }, &di2);

    try std.testing.expectError(CborError.Malformed, decode(allocator, &.{ 0b01000011, 0x0a }));
    try std.testing.expectError(CborError.Malformed, decode(allocator, &.{ 0b01000101, 0x0a, 0xb, 0xc }));
}

test "MT3: decode cbor text string" {
    const allocator = std.testing.allocator;

    try test_data_item(&.{0x60}, try DataItem.text(&.{}, .{ .allocator = allocator }));

    const exp1 = try DataItem.text("a", .{ .allocator = allocator });
    defer exp1.deinit(allocator);
    const di1 = try decode(allocator, &.{ 0x61, 0x61 });
    defer di1.deinit(allocator);
    try std.testing.expectEqualSlices(u8, exp1.text, di1.text);
    try std.testing.expect(exp1.equal(&di1));

    const exp2 = try DataItem.text("IETF", .{ .allocator = allocator });
    defer exp2.deinit(allocator);
    const di2 = try decode(allocator, &.{ 0x64, 0x49, 0x45, 0x54, 0x46 });
    defer di2.deinit(allocator);
    try std.testing.expectEqualSlices(u8, exp2.text, di2.text);
    try std.testing.expect(exp2.equal(&di2));

    const exp3 = try DataItem.text("\"\\", .{ .allocator = allocator });
    defer exp3.deinit(allocator);
    const di3 = try decode(allocator, &.{ 0x62, 0x22, 0x5c });
    defer di3.deinit(allocator);
    try std.testing.expectEqualSlices(u8, exp3.text, di3.text);
    try std.testing.expect(exp3.equal(&di3));

    try std.testing.expect(!exp1.equal(&di2));
    try std.testing.expect(!exp1.equal(&di3));
    try std.testing.expect(!exp2.equal(&di3));

    // TODO: test unicode https://www.rfc-editor.org/rfc/rfc8949.html#name-examples-of-encoded-cbor-da
}

test "MT4: decode cbor array" {
    const allocator = std.testing.allocator;

    const exp1 = try DataItem.array(&.{}, .{ .allocator = allocator });
    defer exp1.deinit(allocator);
    const di1 = try decode(allocator, &.{0x80});
    defer di1.deinit(allocator);
    try std.testing.expect(exp1.equal(&di1));

    const exp2 = try DataItem.array(&.{ DataItem.int(1), DataItem.int(2), DataItem.int(3) }, .{ .allocator = allocator });
    defer exp2.deinit(allocator);
    const di2 = try decode(allocator, &.{ 0x83, 0x01, 0x02, 0x03 });
    defer di2.deinit(allocator);
    try std.testing.expect(exp2.equal(&di2));

    const exp3 = try DataItem.array(&.{ DataItem.int(1), try DataItem.array(&.{ DataItem.int(2), DataItem.int(3) }, .{ .allocator = allocator }), try DataItem.array(&.{ DataItem.int(4), DataItem.int(5) }, .{ .allocator = allocator }) }, .{ .allocator = allocator });
    defer exp3.deinit(allocator);
    const di3 = try decode(allocator, &.{ 0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05 });
    defer di3.deinit(allocator);
    try std.testing.expect(exp3.equal(&di3));

    const exp4 = try DataItem.array(&.{ DataItem.int(1), DataItem.int(2), DataItem.int(3), DataItem.int(4), DataItem.int(5), DataItem.int(6), DataItem.int(7), DataItem.int(8), DataItem.int(9), DataItem.int(10), DataItem.int(11), DataItem.int(12), DataItem.int(13), DataItem.int(14), DataItem.int(15), DataItem.int(16), DataItem.int(17), DataItem.int(18), DataItem.int(19), DataItem.int(20), DataItem.int(21), DataItem.int(22), DataItem.int(23), DataItem.int(24), DataItem.int(25) }, .{ .allocator = allocator });
    defer exp4.deinit(allocator);
    const di4 = try decode(allocator, &.{ 0x98, 0x19, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x18, 0x18, 0x19 });
    defer di4.deinit(allocator);
    try std.testing.expect(exp4.equal(&di4));

    try std.testing.expect(!exp1.equal(&di2));
    try std.testing.expect(!exp1.equal(&di3));
    try std.testing.expect(!exp1.equal(&di4));
    try std.testing.expect(!exp2.equal(&di3));
    try std.testing.expect(!exp2.equal(&di4));
    try std.testing.expect(!exp3.equal(&di4));
}

test "MT5: decode empty cbor map" {
    const allocator = std.testing.allocator;

    const exp1 = try DataItem.map(&.{}, .{ .allocator = allocator });
    defer exp1.deinit(allocator);
    const di1 = try decode(allocator, &.{0xa0});
    defer di1.deinit(allocator);
    try std.testing.expect(exp1.equal(&di1));
}

test "MT5: decode cbor map {1:2,3:4}" {
    const allocator = std.testing.allocator;

    const exp1 = try DataItem.map(&.{ Pair.new(DataItem.int(1), DataItem.int(2)), Pair.new(DataItem.int(3), DataItem.int(4)) }, .{ .allocator = allocator });
    defer exp1.deinit(allocator);
    const di1 = try decode(allocator, &.{ 0xa2, 0x01, 0x02, 0x03, 0x04 });
    defer di1.deinit(allocator);
    try std.testing.expect(exp1.equal(&di1));
}

test "MT5: decode cbor map {\"a\":1,\"b\":[2,3]}" {
    const allocator = std.testing.allocator;

    const exp1 = try DataItem.map(&.{ Pair.new(try DataItem.text("a", .{ .allocator = allocator }), DataItem.int(1)), Pair.new(try DataItem.text("b", .{ .allocator = allocator }), try DataItem.array(&.{ DataItem.int(2), DataItem.int(3) }, .{ .allocator = allocator })) }, .{ .allocator = allocator });
    defer exp1.deinit(allocator);
    const di1 = try decode(allocator, &.{ 0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x82, 0x02, 0x03 });
    defer di1.deinit(allocator);
    try std.testing.expect(exp1.equal(&di1));
}

test "MT5: decode cbor map within array [\"a\",{\"b\":\"c\"}]" {
    const allocator = std.testing.allocator;

    const exp1 = try DataItem.array(&.{ try DataItem.text("a", .{ .allocator = allocator }), try DataItem.map(&.{Pair.new(try DataItem.text("b", .{ .allocator = allocator }), try DataItem.text("c", .{ .allocator = allocator }))}, .{ .allocator = allocator }) }, .{ .allocator = allocator });
    defer exp1.deinit(allocator);
    const di1 = try decode(allocator, &.{ 0x82, 0x61, 0x61, 0xa1, 0x61, 0x62, 0x61, 0x63 });
    defer di1.deinit(allocator);
    try std.testing.expect(exp1.equal(&di1));
}

test "MT5: decode cbor map of text pairs" {
    const allocator = std.testing.allocator;

    const exp1 = try DataItem.map(&.{ Pair.new(try DataItem.text("a", .{ .allocator = allocator }), try DataItem.text("A", .{ .allocator = allocator })), Pair.new(try DataItem.text("b", .{ .allocator = allocator }), try DataItem.text("B", .{ .allocator = allocator })), Pair.new(try DataItem.text("c", .{ .allocator = allocator }), try DataItem.text("C", .{ .allocator = allocator })), Pair.new(try DataItem.text("d", .{ .allocator = allocator }), try DataItem.text("D", .{ .allocator = allocator })), Pair.new(try DataItem.text("e", .{ .allocator = allocator }), try DataItem.text("E", .{ .allocator = allocator })) }, .{ .allocator = allocator });
    defer exp1.deinit(allocator);
    const di1 = try decode(allocator, &.{ 0xa5, 0x61, 0x61, 0x61, 0x41, 0x61, 0x62, 0x61, 0x42, 0x61, 0x63, 0x61, 0x43, 0x61, 0x64, 0x61, 0x44, 0x61, 0x65, 0x61, 0x45 });
    defer di1.deinit(allocator);
    try std.testing.expect(exp1.equal(&di1));
}

test "MT6: decode cbor tagged data item 1(1363896240)" {
    const allocator = std.testing.allocator;

    const exp1 = try DataItem.tagged(allocator, 1, DataItem.int(1363896240));
    defer exp1.deinit(allocator);
    const di1 = try decode(allocator, &.{ 0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0 });
    defer di1.deinit(allocator);
    try std.testing.expect(exp1.equal(&di1));
}

test "MT6: decode cbor tagged data item 32(\"http://www.example.com\")" {
    const allocator = std.testing.allocator;

    const exp1 = try DataItem.tagged(allocator, 32, try DataItem.text("http://www.example.com", .{ .allocator = allocator }));
    defer exp1.deinit(allocator);
    const di1 = try decode(allocator, &.{ 0xd8, 0x20, 0x76, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d });
    defer di1.deinit(allocator);
    try std.testing.expect(exp1.equal(&di1));
    try std.testing.expectEqualStrings(exp1.tag.content.text, di1.tag.content.text);
}

test "MT7: decode f16 0.0" {
    const allocator = std.testing.allocator;

    var expected = DataItem.float16(0.0);
    var ne1 = DataItem.float16(0.1);
    var ne2 = DataItem.float16(-0.1);
    var ne3 = DataItem.float32(0.0);
    var ne4 = DataItem.float64(0.0);
    var di = try decode(allocator, &.{ 0xf9, 0x00, 0x00 });

    try std.testing.expect(di.equal(&expected));
    try std.testing.expect(!di.equal(&ne1));
    try std.testing.expect(!di.equal(&ne2));
    try std.testing.expect(!di.equal(&ne3));
    try std.testing.expect(!di.equal(&ne4));
}

test "MT7: decode f16 -0.0" {
    const allocator = std.testing.allocator;

    var expected = DataItem{ .float = Float{ .float16 = -0.0 } };
    var di = try decode(allocator, &.{ 0xf9, 0x80, 0x00 });

    try std.testing.expectEqual(expected.float.float16, di.float.float16);
    //try std.testing.expect(di.equal(&expected));
}

test "MT7: decode f16 1.0" {
    const allocator = std.testing.allocator;

    var expected = DataItem{ .float = Float{ .float16 = 1.0 } };
    var di = try decode(allocator, &.{ 0xf9, 0x3c, 0x00 });

    try std.testing.expect(di.equal(&expected));
}

test "MT7: decode f16 1.5" {
    const allocator = std.testing.allocator;

    var expected = DataItem{ .float = Float{ .float16 = 1.5 } };
    var di = try decode(allocator, &.{ 0xf9, 0x3e, 0x00 });

    try std.testing.expect(di.equal(&expected));
}

test "MT7: decode f16 5.960464477539063e-8" {
    const allocator = std.testing.allocator;

    var expected = DataItem{ .float = Float{ .float16 = 5.960464477539063e-8 } };
    var di = try decode(allocator, &.{ 0xf9, 0x00, 0x01 });

    try std.testing.expect(di.equal(&expected));
}

test "MT7: decode f16 0.00006103515625" {
    const allocator = std.testing.allocator;

    var expected = DataItem{ .float = Float{ .float16 = 0.00006103515625 } };
    var di = try decode(allocator, &.{ 0xf9, 0x04, 0x00 });

    try std.testing.expect(di.equal(&expected));
}

test "MT7: decode f16 -4.0" {
    const allocator = std.testing.allocator;

    var expected = DataItem{ .float = Float{ .float16 = -4.0 } };
    var di = try decode(allocator, &.{ 0xf9, 0xc4, 0x00 });

    try std.testing.expect(di.equal(&expected));
}

test "MT7: decode f32 100000.0" {
    const allocator = std.testing.allocator;

    var expected = DataItem{ .float = Float{ .float32 = 100000.0 } };
    var di = try decode(allocator, &.{ 0xfa, 0x47, 0xc3, 0x50, 0x00 });

    try std.testing.expect(di.equal(&expected));
}

test "MT7: decode f32 3.4028234663852886e+38" {
    const allocator = std.testing.allocator;

    var expected = DataItem{ .float = Float{ .float32 = 3.4028234663852886e+38 } };
    var di = try decode(allocator, &.{ 0xfa, 0x7f, 0x7f, 0xff, 0xff });

    try std.testing.expect(di.equal(&expected));
}

test "MT7: decode f64 1.1" {
    const allocator = std.testing.allocator;

    var expected = DataItem{ .float = Float{ .float64 = 1.1 } };
    var di = try decode(allocator, &.{ 0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a });

    try std.testing.expect(di.equal(&expected));
}

test "MT7: decode f64 1.0e+300" {
    const allocator = std.testing.allocator;

    var expected = DataItem{ .float = Float{ .float64 = 1.0e+300 } };
    var di = try decode(allocator, &.{ 0xfb, 0x7e, 0x37, 0xe4, 0x3c, 0x88, 0x00, 0x75, 0x9c });

    try std.testing.expect(di.equal(&expected));
}

test "MT7: decode f64 -4.1" {
    const allocator = std.testing.allocator;

    var expected = DataItem{ .float = Float{ .float64 = -4.1 } };
    var di = try decode(allocator, &.{ 0xfb, 0xc0, 0x10, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 });

    try std.testing.expect(di.equal(&expected));
}

test "MT7: simple value" {
    const allocator = std.testing.allocator;

    var expected1 = DataItem.False();
    var di1 = try decode(allocator, &.{0xf4});
    try std.testing.expect(di1.equal(&expected1));

    var expected2 = DataItem.True();
    var di2 = try decode(allocator, &.{0xf5});
    try std.testing.expect(di2.equal(&expected2));

    var expected3 = DataItem.Null();
    var di3 = try decode(allocator, &.{0xf6});
    try std.testing.expect(di3.equal(&expected3));

    var expected4 = DataItem.Undefined();
    var di4 = try decode(allocator, &.{0xf7});
    try std.testing.expect(di4.equal(&expected4));
}

test "decode WebAuthn attestationObject" {
    const allocator = std.testing.allocator;
    const attestationObject = try std.fs.cwd().openFile("data/WebAuthnCreate.dat", .{ .mode = .read_only });
    defer attestationObject.close();
    const bytes = try attestationObject.readToEndAlloc(allocator, 4096);
    defer allocator.free(bytes);

    var di = try decode(allocator, bytes);
    defer di.deinit(allocator);

    try std.testing.expect(di.isMap());

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    const fmt = di.getValueByString("fmt");
    try std.testing.expect(fmt.?.isText());
    try std.testing.expectEqualStrings("fido-u2f", fmt.?.text);

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    const attStmt = di.getValueByString("attStmt");
    try std.testing.expect(attStmt.?.isMap());
    const authData = di.getValueByString("authData");
    try std.testing.expect(authData.?.isBytes());

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    try std.testing.expectEqual(@as(usize, 196), authData.?.bytes.len);

    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    const sig = attStmt.?.getValueByString("sig");
    try std.testing.expect(sig.?.isBytes());
    try std.testing.expectEqual(@as(usize, 71), sig.?.bytes.len);

    const x5c = attStmt.?.getValueByString("x5c");
    try std.testing.expect(x5c.?.isArray());
    try std.testing.expectEqual(@as(usize, 1), x5c.?.array.len);

    const x5c_stmt = x5c.?.get(0);
    try std.testing.expect(x5c_stmt.?.isBytes());
    try std.testing.expectEqual(@as(usize, 704), x5c_stmt.?.bytes.len);
}

test "MT0: encode cbor unsigned integer value" {
    const allocator = std.testing.allocator;

    const di1 = DataItem{ .int = 0 };
    const cbor1 = try encodeAlloc(allocator, &di1);
    defer allocator.free(cbor1);
    try std.testing.expectEqualSlices(u8, &.{0x00}, cbor1);

    const di2 = DataItem{ .int = 23 };
    const cbor2 = try encodeAlloc(allocator, &di2);
    defer allocator.free(cbor2);
    try std.testing.expectEqualSlices(u8, &.{0x17}, cbor2);

    const di3 = DataItem{ .int = 24 };
    const cbor3 = try encodeAlloc(allocator, &di3);
    defer allocator.free(cbor3);
    try std.testing.expectEqualSlices(u8, &.{ 0x18, 0x18 }, cbor3);

    const di4 = DataItem{ .int = 255 };
    const cbor4 = try encodeAlloc(allocator, &di4);
    defer allocator.free(cbor4);
    try std.testing.expectEqualSlices(u8, &.{ 0x18, 0xff }, cbor4);

    const di5 = DataItem{ .int = 256 };
    const cbor5 = try encodeAlloc(allocator, &di5);
    defer allocator.free(cbor5);
    try std.testing.expectEqualSlices(u8, &.{ 0x19, 0x01, 0x00 }, cbor5);

    const di6 = DataItem{ .int = 1000 };
    const cbor6 = try encodeAlloc(allocator, &di6);
    defer allocator.free(cbor6);
    try std.testing.expectEqualSlices(u8, &.{ 0x19, 0x03, 0xe8 }, cbor6);

    const di7 = DataItem{ .int = 65535 };
    const cbor7 = try encodeAlloc(allocator, &di7);
    defer allocator.free(cbor7);
    try std.testing.expectEqualSlices(u8, &.{ 0x19, 0xff, 0xff }, cbor7);

    const di8 = DataItem{ .int = 65536 };
    const cbor8 = try encodeAlloc(allocator, &di8);
    defer allocator.free(cbor8);
    try std.testing.expectEqualSlices(u8, &.{ 0x1a, 0x00, 0x01, 0x00, 0x00 }, cbor8);

    const di9 = DataItem{ .int = 4294967295 };
    const cbor9 = try encodeAlloc(allocator, &di9);
    defer allocator.free(cbor9);
    try std.testing.expectEqualSlices(u8, &.{ 0x1a, 0xff, 0xff, 0xff, 0xff }, cbor9);

    const di10 = DataItem{ .int = 12345678900 };
    const cbor10 = try encodeAlloc(allocator, &di10);
    defer allocator.free(cbor10);
    try std.testing.expectEqualSlices(u8, &.{ 0x1b, 0x00, 0x00, 0x00, 0x02, 0xdf, 0xdc, 0x1c, 0x34 }, cbor10);

    const di11 = DataItem{ .int = 18446744073709551615 };
    const cbor11 = try encodeAlloc(allocator, &di11);
    defer allocator.free(cbor11);
    try std.testing.expectEqualSlices(u8, &.{ 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, cbor11);
}

test "MT1: encode cbor signed integer value" {
    const allocator = std.testing.allocator;

    const di1 = DataItem{ .int = -1 };
    const cbor1 = try encodeAlloc(allocator, &di1);
    defer allocator.free(cbor1);
    try std.testing.expectEqualSlices(u8, &.{0x20}, cbor1);

    const di2 = DataItem{ .int = -3 };
    const cbor2 = try encodeAlloc(allocator, &di2);
    defer allocator.free(cbor2);
    try std.testing.expectEqualSlices(u8, &.{0x22}, cbor2);

    const di3 = DataItem{ .int = -100 };
    const cbor3 = try encodeAlloc(allocator, &di3);
    defer allocator.free(cbor3);
    try std.testing.expectEqualSlices(u8, &.{ 0x38, 0x63 }, cbor3);

    const di4 = DataItem{ .int = -1000 };
    const cbor4 = try encodeAlloc(allocator, &di4);
    defer allocator.free(cbor4);
    try std.testing.expectEqualSlices(u8, &.{ 0x39, 0x03, 0xe7 }, cbor4);

    const di5 = DataItem{ .int = -998877 };
    const cbor5 = try encodeAlloc(allocator, &di5);
    defer allocator.free(cbor5);
    try std.testing.expectEqualSlices(u8, &.{ 0x3a, 0x00, 0x0f, 0x3d, 0xdc }, cbor5);

    const di6 = DataItem{ .int = -18446744073709551616 };
    const cbor6 = try encodeAlloc(allocator, &di6);
    defer allocator.free(cbor6);
    try std.testing.expectEqualSlices(u8, &.{ 0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, cbor6);
}

test "MT2: encode cbor byte string" {
    const allocator = std.testing.allocator;

    var di1 = try DataItem.bytes(&.{}, .{ .allocator = allocator });
    defer di1.deinit(allocator);
    const cbor1 = try encodeAlloc(allocator, &di1);
    defer allocator.free(cbor1);
    try std.testing.expectEqualSlices(u8, &.{0b01000000}, cbor1);

    var di2 = try DataItem.bytes(&.{10}, .{ .allocator = allocator });
    defer di2.deinit(allocator);
    const cbor2 = try encodeAlloc(allocator, &di2);
    defer allocator.free(cbor2);
    try std.testing.expectEqualSlices(u8, &.{ 0x41, 0x0a }, cbor2);

    var di3 = try DataItem.bytes(&.{ 10, 11, 12, 13, 14 }, .{ .allocator = allocator });
    defer di3.deinit(allocator);
    const cbor3 = try encodeAlloc(allocator, &di3);
    defer allocator.free(cbor3);
    try std.testing.expectEqualSlices(u8, &.{ 0x45, 0x0a, 0xb, 0xc, 0xd, 0xe }, cbor3);

    var di4 = try DataItem.bytes(&.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19 }, .{ .allocator = allocator });
    defer di4.deinit(allocator);
    const cbor4 = try encodeAlloc(allocator, &di4);
    defer allocator.free(cbor4);
    try std.testing.expectEqualSlices(u8, &.{ 0x58, 0x19, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19 }, cbor4);
}

test "MT3: encode cbor text string" {
    const allocator = std.testing.allocator;

    var di1 = try DataItem.text(&.{}, .{ .allocator = allocator });
    defer di1.deinit(allocator);
    const cbor1 = try encodeAlloc(allocator, &di1);
    defer allocator.free(cbor1);
    try std.testing.expectEqualSlices(u8, &.{0x60}, cbor1);

    var di2 = try DataItem.text("a", .{ .allocator = allocator });
    defer di2.deinit(allocator);
    const cbor2 = try encodeAlloc(allocator, &di2);
    defer allocator.free(cbor2);
    try std.testing.expectEqualSlices(u8, &.{ 0x61, 0x61 }, cbor2);

    var di3 = try DataItem.text("IETF", .{ .allocator = allocator });
    defer di3.deinit(allocator);
    const cbor3 = try encodeAlloc(allocator, &di3);
    defer allocator.free(cbor3);
    try std.testing.expectEqualSlices(u8, &.{ 0x64, 0x49, 0x45, 0x54, 0x46 }, cbor3);

    var di4 = try DataItem.text("\"\\", .{ .allocator = allocator });
    defer di4.deinit(allocator);
    const cbor4 = try encodeAlloc(allocator, &di4);
    defer allocator.free(cbor4);
    try std.testing.expectEqualSlices(u8, &.{ 0x62, 0x22, 0x5c }, cbor4);

    // TODO: test unicode https://www.rfc-editor.org/rfc/rfc8949.html#name-examples-of-encoded-cbor-da
}

test "MT4: encode cbor array" {
    const allocator = std.testing.allocator;

    var di1 = try DataItem.array(&.{}, .{ .allocator = allocator });
    defer di1.deinit(allocator);
    const cbor1 = try encodeAlloc(allocator, &di1);
    defer allocator.free(cbor1);
    try std.testing.expectEqualSlices(u8, &.{0x80}, cbor1);

    var di2 = try DataItem.array(&.{ DataItem.int(1), DataItem.int(2), DataItem.int(3) }, .{ .allocator = allocator });
    defer di2.deinit(allocator);
    const cbor2 = try encodeAlloc(allocator, &di2);
    defer allocator.free(cbor2);
    try std.testing.expectEqualSlices(u8, &.{ 0x83, 0x01, 0x02, 0x03 }, cbor2);

    const di3 = try DataItem.array(&.{ DataItem.int(1), try DataItem.array(&.{ DataItem.int(2), DataItem.int(3) }, .{ .allocator = allocator }), try DataItem.array(&.{ DataItem.int(4), DataItem.int(5) }, .{ .allocator = allocator }) }, .{ .allocator = allocator });
    defer di3.deinit(allocator);
    const cbor3 = try encodeAlloc(allocator, &di3);
    defer allocator.free(cbor3);
    try std.testing.expectEqualSlices(u8, &.{ 0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05 }, cbor3);

    const di4 = try DataItem.array(&.{ DataItem.int(1), DataItem.int(2), DataItem.int(3), DataItem.int(4), DataItem.int(5), DataItem.int(6), DataItem.int(7), DataItem.int(8), DataItem.int(9), DataItem.int(10), DataItem.int(11), DataItem.int(12), DataItem.int(13), DataItem.int(14), DataItem.int(15), DataItem.int(16), DataItem.int(17), DataItem.int(18), DataItem.int(19), DataItem.int(20), DataItem.int(21), DataItem.int(22), DataItem.int(23), DataItem.int(24), DataItem.int(25) }, .{ .allocator = allocator });
    defer di4.deinit(allocator);
    const cbor4 = try encodeAlloc(allocator, &di4);
    defer allocator.free(cbor4);
    try std.testing.expectEqualSlices(u8, &.{ 0x98, 0x19, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x18, 0x18, 0x19 }, cbor4);
}

test "MT5: encode empty cbor map" {
    const allocator = std.testing.allocator;

    var di = try DataItem.map(&.{}, .{ .allocator = allocator });
    defer di.deinit(allocator);
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{0xa0}, cbor);
}

test "MT5: encode cbor map {1:2,3:4}" {
    const allocator = std.testing.allocator;

    var di = try DataItem.map(&.{ Pair.new(DataItem.int(1), DataItem.int(2)), Pair.new(DataItem.int(3), DataItem.int(4)) }, .{ .allocator = allocator });
    defer di.deinit(allocator);
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{ 0xa2, 0x01, 0x02, 0x03, 0x04 }, cbor);

    // Keys should be sorted in asc order.
    // TODO: sorting currently disabled (see issues)
    // var di2 = try DataItem.map(allocator, &.{ Pair.new(DataItem.int(3), DataItem.int(4)), Pair.new(DataItem.int(1), DataItem.int(2)) });
    // defer di2.deinit(allocator);
    // const cbor2 = try encodeAlloc(allocator, &di2);
    // defer allocator.free(cbor2);
    // try std.testing.expectEqualSlices(u8, &.{ 0xa2, 0x01, 0x02, 0x03, 0x04 }, cbor2);
}

test "MT6: encode cbor tagged data item 1(1363896240)" {
    const allocator = std.testing.allocator;

    var di = try DataItem.tagged(allocator, 1, DataItem.int(1363896240));
    defer di.deinit(allocator);
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{ 0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0 }, cbor);
}

test "MT6: encode cbor tagged data item 32(\"http://www.example.com\")" {
    const allocator = std.testing.allocator;

    var di = try DataItem.tagged(allocator, 32, try DataItem.text("http://www.example.com", .{ .allocator = allocator }));
    defer di.deinit(allocator);
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{ 0xd8, 0x20, 0x76, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d }, cbor);
}

test "MT7: encode f16 0.0" {
    const allocator = std.testing.allocator;

    var di = DataItem{ .float = Float{ .float16 = 0.0 } };
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{ 0xf9, 0x00, 0x00 }, cbor);
}

test "MT7: encode f16 -0.0" {
    const allocator = std.testing.allocator;

    var di = DataItem{ .float = Float{ .float16 = -0.0 } };
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{ 0xf9, 0x80, 0x00 }, cbor);
}

test "MT7: encode f16 1.0" {
    const allocator = std.testing.allocator;

    var di = DataItem{ .float = Float{ .float16 = 1.0 } };
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{ 0xf9, 0x3c, 0x00 }, cbor);
}

test "MT7: encode f16 1.5" {
    const allocator = std.testing.allocator;

    var di = DataItem{ .float = Float{ .float16 = 1.5 } };
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{ 0xf9, 0x3e, 0x00 }, cbor);
}

test "MT7: encode f16 5.960464477539063e-8" {
    const allocator = std.testing.allocator;

    var di = DataItem{ .float = Float{ .float16 = 5.960464477539063e-8 } };
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{ 0xf9, 0x00, 0x01 }, cbor);
}

test "MT7: encode f16 0.00006103515625" {
    const allocator = std.testing.allocator;

    var di = DataItem{ .float = Float{ .float16 = 0.00006103515625 } };
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{ 0xf9, 0x04, 0x00 }, cbor);
}

test "MT7: encode f16 -4.0" {
    const allocator = std.testing.allocator;

    var di = DataItem{ .float = Float{ .float16 = -4.0 } };
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{ 0xf9, 0xc4, 0x00 }, cbor);
}

test "MT7: encode f32 100000.0" {
    const allocator = std.testing.allocator;

    var di = DataItem{ .float = Float{ .float32 = 100000.0 } };
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{ 0xfa, 0x47, 0xc3, 0x50, 0x00 }, cbor);
}

test "MT7: encode f32 3.4028234663852886e+38" {
    const allocator = std.testing.allocator;

    var di = DataItem{ .float = Float{ .float32 = 3.4028234663852886e+38 } };
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{ 0xfa, 0x7f, 0x7f, 0xff, 0xff }, cbor);
}

test "MT7: encode f64 1.1" {
    const allocator = std.testing.allocator;

    var di = DataItem{ .float = Float{ .float64 = 1.1 } };
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{ 0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a }, cbor);
}

test "MT7: encode f64 1.0e+300" {
    const allocator = std.testing.allocator;

    var di = DataItem{ .float = Float{ .float64 = 1.0e+300 } };
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{ 0xfb, 0x7e, 0x37, 0xe4, 0x3c, 0x88, 0x00, 0x75, 0x9c }, cbor);
}

test "MT7: encode f64 -4.1" {
    const allocator = std.testing.allocator;

    var di = DataItem{ .float = Float{ .float64 = -4.1 } };
    const cbor = try encodeAlloc(allocator, &di);
    defer allocator.free(cbor);
    try std.testing.expectEqualSlices(u8, &.{ 0xfb, 0xc0, 0x10, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 }, cbor);
}

test "MT7: encode simple values" {
    const allocator = std.testing.allocator;

    var di1 = DataItem.True();
    const cbor1 = try encodeAlloc(allocator, &di1);
    defer allocator.free(cbor1);
    try std.testing.expectEqualSlices(u8, &.{0xf5}, cbor1);

    var di2 = DataItem.False();
    const cbor2 = try encodeAlloc(allocator, &di2);
    defer allocator.free(cbor2);
    try std.testing.expectEqualSlices(u8, &.{0xf4}, cbor2);

    var di3 = DataItem.Null();
    const cbor3 = try encodeAlloc(allocator, &di3);
    defer allocator.free(cbor3);
    try std.testing.expectEqualSlices(u8, &.{0xf6}, cbor3);

    var di4 = DataItem.Undefined();
    const cbor4 = try encodeAlloc(allocator, &di4);
    defer allocator.free(cbor4);
    try std.testing.expectEqualSlices(u8, &.{0xf7}, cbor4);
}

test "MT0,1: DataItem{ .int = 30 } to json" {
    const allocator = std.testing.allocator;

    const di = DataItem{ .int = 30 };

    var string = std.ArrayList(u8).init(allocator);
    defer string.deinit();
    try std.json.stringify(di, .{}, string.writer());

    try std.testing.expectEqualStrings("30", string.items);
}

test "MT2: DataItem to json" {
    const allocator = std.testing.allocator;

    const di = try DataItem.bytes(&.{ 0x95, 0x28, 0xe0, 0x8f, 0x32, 0xda, 0x3d, 0x36, 0x83, 0xc4, 0x6a, 0x1c, 0x36, 0x58, 0xb4, 0x86, 0x47, 0x2b }, .{ .allocator = allocator });
    defer di.deinit(allocator);

    var string = std.ArrayList(u8).init(allocator);
    defer string.deinit();
    try std.json.stringify(di, .{}, string.writer());

    try std.testing.expectEqualStrings("\"lSjgjzLaPTaDxGocNli0hkcr\"", string.items);
}

test "MT3: DataItem to json" {
    const allocator = std.testing.allocator;

    const di = try DataItem.text("fido-u2f", .{ .allocator = allocator });
    defer di.deinit(allocator);

    var string = std.ArrayList(u8).init(allocator);
    defer string.deinit();
    try std.json.stringify(di, .{}, string.writer());

    try std.testing.expectEqualStrings("\"fido-u2f\"", string.items);
}

test "MT4: DataItem to json" {
    const allocator = std.testing.allocator;

    const di = try DataItem.array(&.{ DataItem.int(1), DataItem.int(2), DataItem.int(3) }, .{ .allocator = allocator });
    defer di.deinit(allocator);

    var string = std.ArrayList(u8).init(allocator);
    defer string.deinit();
    try std.json.stringify(di, .{}, string.writer());

    try std.testing.expectEqualStrings("[1,2,3]", string.items);
}

test "MT5: DataItem to json" {
    const allocator = std.testing.allocator;

    const di = try DataItem.map(&.{ Pair.new(try DataItem.text("a", .{ .allocator = allocator }), DataItem.int(1)), Pair.new(try DataItem.text("b", .{ .allocator = allocator }), try DataItem.array(&.{ DataItem.int(2), DataItem.int(3) }, .{ .allocator = allocator })) }, .{ .allocator = allocator });
    defer di.deinit(allocator);

    var string = std.ArrayList(u8).init(allocator);
    defer string.deinit();
    try std.json.stringify(di, .{}, string.writer());

    try std.testing.expectEqualStrings("{\"a\":1,\"b\":[2,3]}", string.items);
}

test "MT6: BigNum and other tagged values to json" {
    const allocator = std.testing.allocator;

    const di1 = try DataItem.unsignedBignum(allocator, &.{ 0xf6, 0x53, 0xd8, 0xf5, 0x55, 0x8b, 0xf2, 0x49, 0x1d, 0x90, 0x96, 0x13, 0x44, 0x8d, 0xd1, 0xd3 });
    defer di1.deinit(allocator);
    const di2 = try DataItem.signedBignum(allocator, &.{ 0xf6, 0x53, 0xd8, 0xf5, 0x55, 0x8b, 0xf2, 0x49, 0x1d, 0x90, 0x96, 0x13, 0x44, 0x8d, 0xd1, 0xd3 });
    defer di2.deinit(allocator);
    const di3 = try DataItem.tagged(allocator, 22, try DataItem.bytes(&.{ 0xf6, 0x53, 0xd8, 0xf5, 0x55, 0x8b, 0xf2, 0x49, 0x1d, 0x90, 0x96, 0x13, 0x44, 0x8d, 0xd1, 0xd3 }, .{ .allocator = allocator }));
    defer di3.deinit(allocator);
    const di4 = try DataItem.tagged(allocator, 23, try DataItem.bytes("abcd", .{ .allocator = allocator }));
    defer di4.deinit(allocator);

    const json1 = try di1.toJson(allocator);
    defer json1.deinit();
    const json2 = try di2.toJson(allocator);
    defer json2.deinit();
    const json3 = try di3.toJson(allocator);
    defer json3.deinit();
    const json4 = try di4.toJson(allocator);
    defer json4.deinit();

    try std.testing.expectEqualStrings("\"9lPY9VWL8kkdkJYTRI3R0w\"", json1.items);
    try std.testing.expectEqualStrings("\"~9lPY9VWL8kkdkJYTRI3R0w\"", json2.items);
    try std.testing.expectEqualStrings("\"9lPY9VWL8kkdkJYTRI3R0w==\"", json3.items);
    try std.testing.expectEqualStrings("\"61626364\"", json4.items);
}

test "MT7: DataItem to json (false, true, null)" {
    const allocator = std.testing.allocator;

    const di1 = DataItem.False();
    const di2 = DataItem.True();
    const di3 = DataItem.Null();
    const di4 = DataItem.Undefined();

    const json1 = try di1.toJson(allocator);
    defer json1.deinit();
    const json2 = try di2.toJson(allocator);
    defer json2.deinit();
    const json3 = try di3.toJson(allocator);
    defer json3.deinit();
    const json4 = try di4.toJson(allocator);
    defer json4.deinit();

    try std.testing.expectEqualStrings("false", json1.items);
    try std.testing.expectEqualStrings("true", json2.items);
    try std.testing.expectEqualStrings("null", json3.items);
    // Any other simple value is represented as the substitue value (null).
    try std.testing.expectEqualStrings("null", json4.items);
}

test "MT7: DataItem to json (float)" {
    const allocator = std.testing.allocator;

    const di1 = DataItem.float64(-4.1);
    //const di2 = DataItem.float32(3.4028234663852886e+38);

    const json1 = try di1.toJson(allocator);
    defer json1.deinit();
    //const json2 = try di2.toJson(allocator);
    //defer json2.deinit();

    try std.testing.expectEqualStrings("-4.1e+00", json1.items);
    //try std.testing.expectEqualStrings("3.4028234663852886e+38", json2.items);
}

test "serialize WebAuthn attestationObject to json" {
    const allocator = std.testing.allocator;
    const attestationObject = try std.fs.cwd().openFile("data/WebAuthnCreate.dat", .{ .mode = .read_only });
    defer attestationObject.close();
    const bytes = try attestationObject.readToEndAlloc(allocator, 4096);
    defer allocator.free(bytes);

    var di = try decode(allocator, bytes);
    defer di.deinit(allocator);

    var json = std.ArrayList(u8).init(allocator);
    defer json.deinit();
    try std.json.stringify(di, .{}, json.writer());

    const expected = "{\"fmt\":\"fido-u2f\",\"attStmt\":{\"sig\":\"MEUCIQDxiq8pf_27Z2osKh-3EnKViLVnMvh5oSuUhhC1AtBb1wIgT-C4h13JDnutnjn1mR9JVfRlE0rXXoknYH5eI3jAqWc\",\"x5c\":[\"MIICvDCCAaSgAwIBAgIEA63wEjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbTELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgNjE3MzA4MzQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQZnoecFi233DnuSkKgRhalswn-ygkvdr4JSPltbpXK5MxlzVSgWc-9x8mzGysdbBhEecLAYfQYqpVLWWosHPoXo2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwIEMDAhBgsrBgEEAYLlHAEBBAQSBBD6K5ncnjlCV4-SSjDSPEEYMAwGA1UdEwEB_wQCMAAwDQYJKoZIhvcNAQELBQADggEBACjrs2f-0djw4onryp_22AdXxg6a5XyxcoybHDjKu72E2SN9qDGsIZSfDy38DDFr_bF1s25joiu7WA6tylKA0HmEDloeJXJiWjv7h2Az2_siqWnJOLic4XE1lAChJS2XAqkSk9VFGelg3SLOiifrBet-ebdQwAL-2QFrcR7JrXRQG9kUy76O2VcSgbdPROsHfOYeywarhalyVSZ-6OOYK_Q_DLIaOC0jXrnkzm2ymMQFQlBAIysrYeEM1wxiFbwDt-lAcbcOEtHEf5ZlWi75nUzlWn8bSx_5FO4TbZ5hIEcUiGRpiIBEMRZlOIm4ZIbZycn_vJOFRTVps0V0S4ygtDc\"]},\"authData\":\"IQkYX2k6AeoaJkH4LVL7ru4KT0fjN03--HCDjeSbDpdBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQLP4zbGAIJF2-iAaUW0bQvgCqA2vSNA3iCGm-91S3ha37_YiJXJDjeWFfnD57wWA6TfjAK7Q3_E_tqM-w4uBytClAQIDJiABIVgg2fTCo1ITbxnJqV2ogkq1zcTVYx68_VvbsL__JTYJEp4iWCDvQEuIB2VXYAeIij7Wq_-0JXtxI1UzJdRQYTy1vJo6Ug\"}";

    try std.testing.expectEqualStrings(expected, json.items);
}

test "MT0,1: json to DataItem{ .int = 30 }" {
    const allocator = std.testing.allocator;

    const j = "30";
    var s = std.json.TokenStream.init(j);
    const d = try DataItem.parseJson(allocator, &s);
    const e = DataItem{ .int = 30 };
    try std.testing.expectEqual(e, d);
}

test "MT0,1: json to DataItem{ .int = 0 }" {
    const allocator = std.testing.allocator;

    const j = "0";
    var s = std.json.TokenStream.init(j);
    const d = try DataItem.parseJson(allocator, &s);
    const e = DataItem{ .int = 0 };
    try std.testing.expectEqual(e, d);
}

test "MT0,1: json to DataItem{ .int = 18446744073709551615 }" {
    const allocator = std.testing.allocator;

    const j = "18446744073709551615";
    var s = std.json.TokenStream.init(j);
    const d = try DataItem.parseJson(allocator, &s);
    const e = DataItem{ .int = 18446744073709551615 };
    try std.testing.expectEqual(e, d);
}

test "MT0,1: json to DataItem{ .int = -18446744073709551616 }" {
    const allocator = std.testing.allocator;

    const j = "-18446744073709551616";
    var s = std.json.TokenStream.init(j);
    const d = try DataItem.parseJson(allocator, &s);
    const e = DataItem{ .int = -18446744073709551616 };
    try std.testing.expectEqual(e, d);
}

test "MT3: json to text string 1" {
    const allocator = std.testing.allocator;

    const j = "\"IETF\"";
    var s = std.json.TokenStream.init(j);
    const d = try DataItem.parseJson(allocator, &s);
    defer d.deinit(allocator);
    const e = try DataItem.text("IETF", .{ .allocator = allocator });
    defer e.deinit(allocator);
    try std.testing.expectEqualStrings(e.text, d.text);
    try std.testing.expect(e.equal(&d));
}

test "MT3: json to text string 2" {
    const allocator = std.testing.allocator;

    const j = "\"\"";
    var s = std.json.TokenStream.init(j);
    const d = try DataItem.parseJson(allocator, &s);
    defer d.deinit(allocator);
    const e = try DataItem.text(&.{}, .{ .allocator = allocator });
    defer e.deinit(allocator);
    try std.testing.expectEqualStrings(e.text, d.text);
    try std.testing.expect(e.equal(&d));
}

test "MT3: json to text string 3" {
    const allocator = std.testing.allocator;

    const j = "\"a\"";
    var s = std.json.TokenStream.init(j);
    const d = try DataItem.parseJson(allocator, &s);
    defer d.deinit(allocator);
    const e = try DataItem.text("a", .{ .allocator = allocator });
    defer e.deinit(allocator);
    try std.testing.expectEqualStrings(e.text, d.text);
    try std.testing.expect(e.equal(&d));
}

test "MT6: bignum 2^64" {
    const allocator = std.testing.allocator;

    const j = "18446744073709551616";
    var s = std.json.TokenStream.init(j);
    const d = try DataItem.parseJson(allocator, &s);
    defer d.deinit(allocator);
    const e = try DataItem.tagged(allocator, 2, try DataItem.bytes(&.{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, .{ .allocator = allocator }));
    defer e.deinit(allocator);
    //try std.testing.expectEqual(e, d);
    try std.testing.expect(d.isTagged());
    try std.testing.expectEqual(@as(u64, 2), d.tag.number);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, d.tag.content.bytes);
    try std.testing.expect(e.equal(&d));
}

test "MT6: bignum 147573952589680980818" {
    const allocator = std.testing.allocator;

    const j = "147573952589680980818";
    var s = std.json.TokenStream.init(j);
    const d = try DataItem.parseJson(allocator, &s);
    defer d.deinit(allocator);
    const e = try DataItem.tagged(allocator, 2, try DataItem.bytes(&.{ 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45, 0xB3, 0x52 }, .{ .allocator = allocator }));
    defer e.deinit(allocator);
    try std.testing.expect(e.equal(&d));
}

test "MT6: bignum -147573952589680980818" {
    const allocator = std.testing.allocator;

    const j = "-147573952589680980818";
    var s = std.json.TokenStream.init(j);
    const d = try DataItem.parseJson(allocator, &s);
    defer d.deinit(allocator);
    const e = try DataItem.tagged(allocator, 3, try DataItem.bytes(&.{ 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45, 0xB3, 0x51 }, .{ .allocator = allocator }));
    defer e.deinit(allocator);
    try std.testing.expect(e.equal(&d));
}

test "MT7: json to f64 0.0" {
    const allocator = std.testing.allocator;

    const j = "0.0";
    var s = std.json.TokenStream.init(j);
    const d = try DataItem.parseJson(allocator, &s);
    const e = DataItem.float64(0.0);
    try std.testing.expectEqual(e, d);
}

test "MT7: json to f64 100000.0" {
    const allocator = std.testing.allocator;

    const j = "100000.0";
    var s = std.json.TokenStream.init(j);
    const d = try DataItem.parseJson(allocator, &s);
    const e = DataItem.float64(100000.0);
    try std.testing.expectEqual(e, d);
}

test "MT7: json to true" {
    const allocator = std.testing.allocator;

    const j = "true";
    var s = std.json.TokenStream.init(j);
    const d = try DataItem.parseJson(allocator, &s);
    const e = DataItem.True();
    try std.testing.expectEqual(e, d);
}

test "MT7: json to false" {
    const allocator = std.testing.allocator;

    const j = "false";
    var s = std.json.TokenStream.init(j);
    const d = try DataItem.parseJson(allocator, &s);
    const e = DataItem.False();
    try std.testing.expectEqual(e, d);
}

test "MT7: json to null" {
    const allocator = std.testing.allocator;

    const j = "null";
    var s = std.json.TokenStream.init(j);
    const d = try DataItem.parseJson(allocator, &s);
    const e = DataItem.Null();
    try std.testing.expectEqual(e, d);
}
