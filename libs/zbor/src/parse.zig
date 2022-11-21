const std = @import("std");
const Allocator = std.mem.Allocator;

const cbor = @import("cbor.zig");
const Error = cbor.Error;
const Type = cbor.Type;
const DataItem = cbor.DataItem;
const Tag = cbor.Tag;
const Pair = cbor.Pair;
const MapIterator = cbor.MapIterator;
const ArrayIterator = cbor.ArrayIterator;
const unsigned_16 = cbor.unsigned_16;
const unsigned_32 = cbor.unsigned_32;
const unsigned_64 = cbor.unsigned_64;
const encode_2 = cbor.encode_2;
const encode_4 = cbor.encode_4;
const encode_8 = cbor.encode_8;

pub const ParseError = error{
    UnsupportedType,
    UnexpectedItem,
    UnexpectedItemValue,
    InvalidKeyType,
    InvalidEnumTag,
    DuplicateCborField,
    UnknownField,
    MissingField,
    AllocatorRequired,
    Overflow,
    OutOfMemory,
    Malformed,
};

pub const StringifyError = error{
    UnsupportedItem,
    OutOfMemory,
};

pub const ParseOptions = struct {
    allocator: ?Allocator = null,

    duplicate_field_behavior: enum {
        UseFirst,
        Error,
    } = .Error,

    ignore_unknown_fields: bool = true,
};

pub fn parse(comptime T: type, item: DataItem, options: ParseOptions) ParseError!T {
    switch (@typeInfo(T)) {
        .Bool => {
            return switch (item.getType()) {
                .False => false,
                .True => true,
                else => ParseError.UnexpectedItem,
            };
        },
        .Float, .ComptimeFloat => {
            return switch (item.getType()) {
                .Float => if (item.float()) |x| @floatCast(T, x) else return ParseError.Malformed,
                else => ParseError.UnexpectedItem,
            };
        },
        .Int, .ComptimeInt => {
            switch (item.getType()) {
                .Int => {
                    const v = if (item.int()) |x| x else return ParseError.Malformed;
                    if (v > std.math.maxInt(T) or v < std.math.minInt(T))
                        return ParseError.Overflow;

                    return @intCast(T, v);
                },
                else => return ParseError.UnexpectedItem,
            }
        },
        .Optional => |optionalInfo| {
            return switch (item.getType()) {
                .Null, .Undefined => null,
                else => try parse(optionalInfo.child, item, options),
            };
        },
        .Enum => |enumInfo| {
            switch (item.getType()) {
                .Int => {
                    const v = if (item.int()) |x| x else return ParseError.Malformed;
                    return try std.meta.intToEnum(T, v);
                },
                .TextString => {
                    const v = if (item.string()) |x| x else return ParseError.Malformed;
                    inline for (enumInfo.fields) |field| {
                        if (cmp(field.name, v)) {
                            return @field(T, field.name);
                        }
                    }
                    return ParseError.InvalidEnumTag;
                },
                else => return ParseError.UnexpectedItem,
            }
        },
        .Struct => |structInfo| {
            switch (item.getType()) {
                .Map => {
                    var r: T = undefined;
                    var fields_seen = [_]bool{false} ** structInfo.fields.len;

                    var v = if (item.map()) |x| x else return ParseError.Malformed;
                    while (v.next()) |kv| {
                        var found = false;

                        if (kv.key.getType() != .TextString and kv.key.getType() != .Int) continue;

                        inline for (structInfo.fields) |field, i| {
                            var match: bool = false;
                            const name = if (field.name.len >= 3 and field.name[field.name.len - 2] == '_' and (field.name[field.name.len - 1] == 'b' or field.name[field.name.len - 1] == 't')) field.name[0 .. field.name.len - 2] else field.name;

                            switch (kv.key.getType()) {
                                .Int => {
                                    const x = if (kv.key.int()) |y| y else return ParseError.Malformed;
                                    const y = s2n(name);
                                    match = x == y;
                                },
                                else => match = std.mem.eql(u8, name, if (kv.key.string()) |x| x else return ParseError.Malformed),
                            }

                            if (match) {
                                if (fields_seen[i]) {
                                    switch (options.duplicate_field_behavior) {
                                        .UseFirst => {
                                            found = true;
                                            break;
                                        },
                                        .Error => return ParseError.DuplicateCborField,
                                    }
                                }

                                @field(r, field.name) = try parse(field.field_type, kv.value, options);

                                fields_seen[i] = true;
                                found = true;
                                break;
                            }
                        }

                        if (!found and !options.ignore_unknown_fields) {
                            return ParseError.UnknownField;
                        }
                    }

                    inline for (structInfo.fields) |field, i| {
                        if (!fields_seen[i]) {
                            switch (@typeInfo(field.field_type)) {
                                .Optional => @field(r, field.name) = null,
                                else => return ParseError.MissingField,
                            }
                        }
                    }

                    return r;
                },
                else => return ParseError.UnexpectedItem,
            }
        },
        .Array => |arrayInfo| {
            switch (item.getType()) {
                .Array => {
                    var v = if (item.array()) |x| x else return ParseError.Malformed;
                    var r: T = undefined;
                    var i: usize = 0;

                    while (i < r.len) : (i += 1) {
                        r[i] = try parse(arrayInfo.child, if (v.next()) |x| x else return ParseError.Malformed, options);
                    }

                    return r;
                },
                else => return ParseError.UnexpectedItem,
            }
        },
        .Pointer => |ptrInfo| {
            const allocator = options.allocator orelse return ParseError.AllocatorRequired;

            switch (ptrInfo.size) {
                .One => {
                    // We use *ptrInfo.child instead of T to allow const and non-const types
                    const r: *ptrInfo.child = try allocator.create(ptrInfo.child);
                    errdefer allocator.destroy(r);
                    r.* = try parse(ptrInfo.child, item, options);
                    return r;
                },
                .Slice => {
                    switch (item.getType()) {
                        .ByteString, .TextString => {
                            const v = if (item.string()) |x| x else return ParseError.Malformed;
                            if (ptrInfo.child != u8) {
                                return ParseError.UnexpectedItem;
                            }

                            var r: []ptrInfo.child = try allocator.alloc(ptrInfo.child, v.len);
                            errdefer allocator.free(r);
                            std.mem.copy(ptrInfo.child, r[0..], v[0..]);
                            return r;
                        },
                        .Array => {
                            var v = if (item.array()) |x| x else return ParseError.Malformed;
                            var arraylist = std.ArrayList(ptrInfo.child).init(allocator);
                            errdefer {
                                // TODO: take care of children
                                arraylist.deinit();
                            }

                            while (v.next()) |elem| {
                                try arraylist.ensureUnusedCapacity(1);
                                const x = try parse(ptrInfo.child, elem, options);
                                arraylist.appendAssumeCapacity(x);
                            }

                            if (ptrInfo.sentinel) |some| {
                                const sentinel_value = @ptrCast(*align(1) const ptrInfo.child, some).*;
                                try arraylist.append(sentinel_value);
                                const output = arraylist.toOwnedSlice();
                                return output[0 .. output.len - 1 :sentinel_value];
                            }

                            return arraylist.toOwnedSlice();
                        },
                        else => return ParseError.UnexpectedItem,
                    }
                },
                else => return Error.UnsupportedType,
            }
        },
        else => return Error.UnsupportedType,
    }
}

pub const StringifyOptions = struct {
    skip_null_fields: bool = true,
    slice_as_text: bool = true,
    enum_as_text: bool = true,
};

pub fn stringify(
    value: anytype,
    options: StringifyOptions,
    out: anytype,
) StringifyError!void {
    const T = @TypeOf(value);
    var head: u8 = 0;
    switch (@typeInfo(T)) {
        .Int, .ComptimeInt => head = if (value < 0) 0x20 else 0,
        .Float, .ComptimeFloat, .Bool, .Null => head = 0xe0,
        .Array => |arrayInfo| {
            if (arrayInfo.child == u8) {
                if (options.slice_as_text and std.unicode.utf8ValidateSlice(value[0..])) {
                    head = 0x60;
                } else {
                    head = 0x40;
                }
            } else {
                head = 0x80;
            }
        },
        .Struct => head = 0xa0, // Struct becomes a Map.
        .Optional => {}, // <- This value will be ignored.
        .Pointer => |ptr_info| switch (ptr_info.size) {
            .Slice => {
                if (ptr_info.child == u8) {
                    if (options.slice_as_text and std.unicode.utf8ValidateSlice(value)) {
                        head = 0x60;
                    } else {
                        head = 0x40;
                    }
                } else {
                    head = 0x80;
                }
            },
            .One => {
                try stringify(value.*, options, out);
                return;
            },
            else => @compileError("Unable to stringify type '" ++ @typeName(T) ++ "'"),
        },
        .Enum => {
            if (options.enum_as_text) head = 0x60 else head = 0;
        },
        .Union => {
            const info = @typeInfo(T).Union;
            if (info.tag_type) |UnionTagType| {
                inline for (info.fields) |u_field| {
                    if (value == @field(UnionTagType, u_field.name)) {
                        try stringify(@field(value, u_field.name), options, out);
                        break;
                    }
                }
                return;
            } else {
                @compileError("Unable to stringify untagged union '" ++ @typeName(T) ++ "'");
            }
        },
        else => {
            return .UnsupportedItem;
        }, // TODO: add remaining options
    }

    var v: u64 = 0;
    switch (@typeInfo(T)) {
        .Int, .ComptimeInt => v = @intCast(u64, if (value < 0) -(value + 1) else value),
        .Float, .ComptimeFloat => {
            // TODO: implement
            // TODO: Encode as small as possible!
            // TODO: Handle values that cant fit in u64 (->tagged)
            return;
        },
        .Bool => v = if (value) 21 else 20,
        .Null => v = 22,
        .Struct => |S| {
            inline for (S.fields) |Field| {
                // don't include void fields
                if (Field.field_type == void) continue;

                // dont't include (optional) null fields
                var emit_field = true;
                if (@typeInfo(Field.field_type) == .Optional) {
                    if (options.skip_null_fields) {
                        if (@field(value, Field.name) == null) {
                            emit_field = false;
                        }
                    }
                }

                if (emit_field) {
                    v += 1;
                }
            }
        },
        .Optional => {
            if (value) |payload| {
                try stringify(payload, options, out);
                return;
            } else {
                try stringify(null, options, out);
                return;
            }
        },
        .Enum => |enumInfo| {
            if (options.enum_as_text) {
                const tmp = @intCast(usize, @enumToInt(value));
                inline for (enumInfo.fields) |field| {
                    if (field.value == tmp) {
                        v = @intCast(u64, field.name.len);
                    }
                }
            } else {
                v = @intCast(u64, @enumToInt(value));
            }
        },
        .Pointer => |ptr_info| v = switch (ptr_info.size) {
            .Slice => @intCast(u64, value.len),
            else => {},
        },
        .Array => {
            v = @intCast(u64, value.len);
        },
        else => unreachable, // caught by the first check
    }

    switch (v) {
        0x00...0x17 => {
            try out.writeByte(head | @intCast(u8, v));
        },
        0x18...0xff => {
            try out.writeByte(head | 24);
            try out.writeByte(@intCast(u8, v));
        },
        0x0100...0xffff => try encode_2(out, head, v),
        0x00010000...0xffffffff => try encode_4(out, head, v),
        0x0000000100000000...0xffffffffffffffff => try encode_8(out, head, v),
    }

    switch (@typeInfo(T)) {
        .Int, .ComptimeInt, .Float, .ComptimeFloat, .Bool, .Null => {},
        .Struct => |S| {
            inline for (S.fields) |Field| {
                // don't include void fields
                if (Field.field_type == void) continue;

                // dont't include (optional) null fields
                var emit_field = true;
                if (@typeInfo(Field.field_type) == .Optional) {
                    if (options.skip_null_fields) {
                        if (@field(value, Field.name) == null) {
                            emit_field = false;
                        }
                    }
                }

                if (emit_field) {
                    var child_options = options;
                    var l = Field.name.len;
                    if (Field.name.len >= 3) {
                        if (Field.name[l - 2] == '_') {
                            if (Field.name[l - 1] == 'b') {
                                l -= 2;
                                child_options.slice_as_text = false;
                            } else if (Field.name[l - 1] == 't') {
                                l -= 2;
                                child_options.slice_as_text = true;
                            }
                        }
                    }

                    if (s2n(Field.name[0..l])) |nr| { // int key
                        try stringify(nr, options, out); // key
                    } else { // str key
                        try stringify(Field.name[0..l], options, out); // key
                    }

                    try stringify(@field(value, Field.name), child_options, out); // value
                }
            }
        },
        .Pointer => |ptr_info| switch (ptr_info.size) {
            .Slice => {
                if (ptr_info.child == u8) {
                    try out.writeAll(value);
                } else {
                    for (value) |x| {
                        try stringify(x, options, out);
                    }
                }
            },
            else => {},
        },
        .Array => |arrayInfo| {
            if (arrayInfo.child == u8) {
                try out.writeAll(value[0..]);
            } else {
                for (value) |x| {
                    try stringify(x, options, out);
                }
            }
        },
        .Enum => |enumInfo| {
            if (options.enum_as_text) {
                const tmp = @enumToInt(value);
                inline for (enumInfo.fields) |field| {
                    if (field.value == tmp) {
                        try out.writeAll(field.name);
                    }
                }
            }
        },
        else => unreachable, // caught by the previous check
    }
}

fn s2n(s: []const u8) ?i65 {
    if (s.len < 1) return null;
    const start: usize = if (s[0] == '-') 1 else 0;

    var x: i64 = 0;

    for (s[start..]) |c| {
        if (c > 57 or c < 48) return null;
        x *= 10;
        x += @intCast(i64, c - 48);
    }

    return if (start == 1) -x else x;
}

fn cmp(l: []const u8, r: []const u8) bool {
    if (l.len != r.len) return false;

    var i: usize = 0;
    while (i < l.len) : (i += 1) {
        if (l[i] != r[i]) return false;
    }
    return true;
}

fn testStringify(e: []const u8, v: anytype, o: StringifyOptions) !void {
    const allocator = std.testing.allocator;
    var str = std.ArrayList(u8).init(allocator);
    defer str.deinit();

    try stringify(v, o, str.writer());
    try std.testing.expectEqualSlices(u8, e, str.items);
}

test "parse boolean" {
    const t = DataItem.new("\xf5");
    const f = DataItem.new("\xf4");
    const u = DataItem.new("\xf7");
    const i = DataItem.new("\x0b");

    try std.testing.expectEqual(true, try parse(bool, t, .{}));
    try std.testing.expectEqual(false, try parse(bool, f, .{}));
    try std.testing.expectError(ParseError.UnexpectedItem, parse(bool, u, .{}));
    try std.testing.expectError(ParseError.UnexpectedItem, parse(bool, i, .{}));
}

test "parse float" {
    const f1 = DataItem.new("\xfb\x3f\xf1\x99\x99\x99\x99\x99\x9a");
    const f2 = DataItem.new("\xFB\x40\x1D\x67\x86\xC2\x26\x80\x9D");
    const f3 = DataItem.new("\xFB\xC0\x28\x1E\xB8\x51\xEB\x85\x1F");

    try std.testing.expectApproxEqRel(try parse(f16, f1, .{}), 1.1, 0.01);
    try std.testing.expectApproxEqRel(try parse(f16, f2, .{}), 7.3511, 0.01);
    try std.testing.expectApproxEqRel(try parse(f32, f2, .{}), 7.3511, 0.01);
    try std.testing.expectApproxEqRel(try parse(f32, f3, .{}), -12.06, 0.01);
    try std.testing.expectApproxEqRel(try parse(f64, f3, .{}), -12.06, 0.01);
}

test "stringify float" {
    // TODO
}

test "parse int" {
    const i_1 = DataItem.new("\x18\xff");
    const i_2 = DataItem.new("\x19\x01\x00");

    try std.testing.expectEqual(try parse(u8, i_1, .{}), 255);
    try std.testing.expectError(ParseError.Overflow, parse(u8, i_2, .{}));
}

test "stringify int" {
    try testStringify("\x00", 0, .{});
    try testStringify("\x01", 1, .{});
    try testStringify("\x0a", 10, .{});
    try testStringify("\x17", 23, .{});
    try testStringify("\x18\x18", 24, .{});
    try testStringify("\x18\x19", 25, .{});
    try testStringify("\x18\x64", 100, .{});
    try testStringify("\x18\x7b", 123, .{});
    try testStringify("\x19\x03\xe8", 1000, .{});
    try testStringify("\x19\x04\xd2", 1234, .{});
    try testStringify("\x1a\x00\x01\xe2\x40", 123456, .{});
    try testStringify("\x1a\x00\x0f\x42\x40", 1000000, .{});
    try testStringify("\x1b\x00\x00\x00\x02\xdf\xdc\x1c\x34", 12345678900, .{});
    try testStringify("\x1b\x00\x00\x00\xe8\xd4\xa5\x10\x00", 1000000000000, .{});
    try testStringify("\x1b\xff\xff\xff\xff\xff\xff\xff\xff", 18446744073709551615, .{});

    try testStringify("\x20", -1, .{});
    try testStringify("\x22", -3, .{});
    try testStringify("\x38\x63", -100, .{});
    try testStringify("\x39\x01\xf3", -500, .{});
    try testStringify("\x39\x03\xe7", -1000, .{});
    try testStringify("\x3a\x00\x0f\x3d\xdc", -998877, .{});
    try testStringify("\x3b\x00\x00\x00\x02\x53\x60\xa2\xce", -9988776655, .{});
    try testStringify("\x3b\xff\xff\xff\xff\xff\xff\xff\xff", -18446744073709551616, .{});
}

test "parse struct: 1" {
    const Config = struct {
        vals: struct { testing: u8, production: u8 },
        uptime: u64,
    };

    const di = DataItem.new("\xa2\x64\x76\x61\x6c\x73\xa2\x67\x74\x65\x73\x74\x69\x6e\x67\x01\x6a\x70\x72\x6f\x64\x75\x63\x74\x69\x6f\x6e\x18\x2a\x66\x75\x70\x74\x69\x6d\x65\x19\x27\x0f");

    const c = try parse(Config, di, .{});

    try std.testing.expectEqual(c.uptime, 9999);
    try std.testing.expectEqual(c.vals.testing, 1);
    try std.testing.expectEqual(c.vals.production, 42);
}

test "parse struct: 2 (optional missing field)" {
    const Config = struct {
        vals: struct { testing: u8, production: ?u8 },
        uptime: u64,
    };

    const di = DataItem.new("\xa2\x64\x76\x61\x6c\x73\xa1\x67\x74\x65\x73\x74\x69\x6e\x67\x01\x66\x75\x70\x74\x69\x6d\x65\x19\x27\x0f");

    const c = try parse(Config, di, .{});

    try std.testing.expectEqual(c.vals.production, null);
}

test "parse struct: 3 (missing field)" {
    const Config = struct {
        vals: struct { testing: u8, production: u8 },
        uptime: u64,
    };

    const di = DataItem.new("\xa2\x64\x76\x61\x6c\x73\xa1\x67\x74\x65\x73\x74\x69\x6e\x67\x01\x66\x75\x70\x74\x69\x6d\x65\x19\x27\x0f");

    try std.testing.expectError(ParseError.MissingField, parse(Config, di, .{}));
}

test "parse struct: 4 (unknown field)" {
    const Config = struct {
        vals: struct { testing: u8 },
        uptime: u64,
    };

    const di = DataItem.new("\xa2\x64\x76\x61\x6c\x73\xa2\x67\x74\x65\x73\x74\x69\x6e\x67\x01\x6a\x70\x72\x6f\x64\x75\x63\x74\x69\x6f\x6e\x18\x2a\x66\x75\x70\x74\x69\x6d\x65\x19\x27\x0f");

    try std.testing.expectError(ParseError.UnknownField, parse(Config, di, .{ .ignore_unknown_fields = false }));
}

test "parse struct: 7" {
    const allocator = std.testing.allocator;

    const Config = struct {
        @"1": struct { @"1": u8, @"2": u8 },
        @"2": u64,
    };

    const di = DataItem.new("\xA2\x01\xA2\x01\x01\x02\x18\x2A\x02\x19\x27\x0F");

    const c = try parse(Config, di, .{ .allocator = allocator });

    try std.testing.expectEqual(c.@"2", 9999);
    try std.testing.expectEqual(c.@"1".@"1", 1);
    try std.testing.expectEqual(c.@"1".@"2", 42);
}

test "parse optional value" {
    const e1: ?u32 = 1234;
    const e2: ?u32 = null;

    try std.testing.expectEqual(e1, try parse(?u32, DataItem.new("\x19\x04\xD2"), .{}));
    try std.testing.expectEqual(e2, try parse(?u32, DataItem.new("\xf6"), .{}));
    try std.testing.expectEqual(e2, try parse(?u32, DataItem.new("\xf7"), .{}));
}

test "stringify optional value" {
    const e1: ?u32 = 1234;
    const e2: ?u32 = null;

    try testStringify("\xf6", e2, .{});
    try testStringify("\x19\x04\xd2", e1, .{});
}

test "parse array: 1" {
    const e = [5]u8{ 1, 2, 3, 4, 5 };
    const di = DataItem.new("\x85\x01\x02\x03\x04\x05");

    const x = try parse([5]u8, di, .{});

    try std.testing.expectEqualSlices(u8, e[0..], x[0..]);
}

test "parse array: 2" {
    const e = [5]?u8{ 1, null, 3, null, 5 };
    const di = DataItem.new("\x85\x01\xF6\x03\xF6\x05");

    const x = try parse([5]?u8, di, .{});

    try std.testing.expectEqualSlices(?u8, e[0..], x[0..]);
}

test "parse pointer" {
    const allocator = std.testing.allocator;

    const e1_1: u32 = 1234;
    const e1: *const u32 = &e1_1;
    const di1 = DataItem.new("\x19\x04\xD2");
    const c1 = try parse(*const u32, di1, .{ .allocator = allocator });
    defer allocator.destroy(c1);
    try std.testing.expectEqual(e1.*, c1.*);

    var e2_1: u32 = 1234;
    const e2: *u32 = &e2_1;
    const di2 = DataItem.new("\x19\x04\xD2");
    const c2 = try parse(*u32, di2, .{ .allocator = allocator });
    defer allocator.destroy(c2);
    try std.testing.expectEqual(e2.*, c2.*);
}

test "parse slice" {
    const allocator = std.testing.allocator;

    var e1: []const u8 = &.{ 1, 2, 3, 4, 5 };
    const di1 = DataItem.new("\x45\x01\x02\x03\x04\x05");
    const c1 = try parse([]const u8, di1, .{ .allocator = allocator });
    defer allocator.free(c1);
    try std.testing.expectEqualSlices(u8, e1, c1);

    var e2 = [5]u8{ 1, 2, 3, 4, 5 };
    const di2 = DataItem.new("\x45\x01\x02\x03\x04\x05");
    const c2 = try parse([]u8, di2, .{ .allocator = allocator });
    defer allocator.free(c2);
    try std.testing.expectEqualSlices(u8, e2[0..], c2);
}

test "stringify simple value" {
    try testStringify("\xf4", false, .{});
    try testStringify("\xf5", true, .{});
    try testStringify("\xf6", null, .{});
}

test "stringify pointer" {
    const x1: u32 = 1234;
    const x1p: *const u32 = &x1;
    const x2 = -18446744073709551616;
    const x2p = &x2;

    try testStringify("\x19\x04\xd2", x1p, .{});
    try testStringify("\x3b\xff\xff\xff\xff\xff\xff\xff\xff", x2p, .{});
}

test "stringify slice" {
    const s1: []const u8 = "a";
    try testStringify("\x61\x61", s1, .{});

    const s2: []const u8 = "IETF";
    try testStringify("\x64\x49\x45\x54\x46", s2, .{});

    const s3: []const u8 = "\"\\";
    try testStringify("\x62\x22\x5c", s3, .{});

    const b1: []const u8 = &.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19 };
    try testStringify(&.{ 0x58, 0x19, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19 }, b1, .{ .slice_as_text = false });

    const b2: []const u8 = "\x10\x11\x12\x13\x14";
    try testStringify("\x45\x10\x11\x12\x13\x14", b2, .{ .slice_as_text = false });
}

test "stringify struct: 1" {
    const Info = struct {
        versions: []const []const u8,
    };

    const i = Info{
        .versions = &.{"FIDO_2_0"},
    };

    try testStringify("\xa1\x68\x76\x65\x72\x73\x69\x6f\x6e\x73\x81\x68\x46\x49\x44\x4f\x5f\x32\x5f\x30", i, .{});
}

test "stringify struct: 2" {
    const Info = struct {
        @"1": []const []const u8,
    };

    const i = Info{
        .@"1" = &.{"FIDO_2_0"},
    };

    try testStringify("\xa1\x01\x81\x68\x46\x49\x44\x4f\x5f\x32\x5f\x30", i, .{});
}

test "stringify struct: 3" {
    const Info = struct {
        @"1": []const []const u8,
        @"2": []const []const u8,
        @"3_b": []const u8,
    };

    const i = Info{
        .@"1" = &.{"FIDO_2_0"},
        .@"2" = &.{},
        .@"3_b" = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    };

    try testStringify("\xa3\x01\x81\x68\x46\x49\x44\x4f\x5f\x32\x5f\x30\x02\x80\x03\x50\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", i, .{});
}

test "stringify struct: 4" {
    const Info = struct {
        @"1": []const []const u8,
        @"2": []const []const u8,
        @"3_b": []const u8,
        @"4": struct {
            plat: bool,
            rk: bool,
            clientPin: ?bool,
            up: bool,
            uv: ?bool,
        },
        @"5": ?u64,
        @"6": ?[]const u64,
    };

    const i = Info{
        .@"1" = &.{"FIDO_2_0"},
        .@"2" = &.{},
        .@"3_b" = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        .@"4" = .{
            .plat = true,
            .rk = true,
            .clientPin = null,
            .up = true,
            .uv = false,
        },
        .@"5" = null,
        .@"6" = null,
    };

    try testStringify("\xa4\x01\x81\x68\x46\x49\x44\x4f\x5f\x32\x5f\x30\x02\x80\x03\x50\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x04\xa4\x64\x70\x6c\x61\x74\xf5\x62\x72\x6b\xf5\x62\x75\x70\xf5\x62\x75\x76\xf4", i, .{});
}

test "parse struct: 5" {
    const allocator = std.testing.allocator;

    const di = DataItem.new("\xa4\x01\x81\x68\x46\x49\x44\x4f\x5f\x32\x5f\x30\x02\x80\x03\x50\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x04\xa4\x64\x70\x6c\x61\x74\xf5\x62\x72\x6b\xf5\x62\x75\x70\xf5\x62\x75\x76\xf4");

    const Info = struct {
        @"1": []const []const u8,
        @"2": []const []const u8,
        @"3_b": []const u8,
        @"4": struct {
            plat: bool,
            rk: bool,
            clientPin: ?bool,
            up: bool,
            uv: ?bool,
        },
        @"5": ?u64,
        @"6": ?[]const u64,
    };

    const i = try parse(Info, di, .{ .allocator = allocator });
    defer {
        allocator.free(i.@"1"[0]);
        allocator.free(i.@"1");
        allocator.free(i.@"2");
        allocator.free(i.@"3_b");
    }

    try std.testing.expectEqualStrings("FIDO_2_0", i.@"1"[0]);
}

test "stringify enum: 1" {
    const Level = enum(u8) {
        high = 7,
        low = 11,
    };

    const allocator = std.testing.allocator;
    var str = std.ArrayList(u8).init(allocator);
    defer str.deinit();

    const high = Level.high;
    const low = Level.low;

    try testStringify("\x07", high, .{ .enum_as_text = false });
    try testStringify("\x0b", low, .{ .enum_as_text = false });
}

test "stringify enum: 2" {
    const Level = enum(u8) {
        high = 7,
        low = 11,
    };

    const allocator = std.testing.allocator;
    var str = std.ArrayList(u8).init(allocator);
    defer str.deinit();

    try testStringify("\x64\x68\x69\x67\x68", Level.high, .{});
    try testStringify("\x63\x6C\x6F\x77", Level.low, .{});
}

test "parse enum: 1" {
    const Level = enum(u8) {
        high = 7,
        low = 11,
    };

    const di1 = DataItem.new("\x64\x68\x69\x67\x68");
    const di2 = DataItem.new("\x63\x6C\x6F\x77");

    const x1 = try parse(Level, di1, .{});
    const x2 = try parse(Level, di2, .{});

    try std.testing.expectEqual(Level.high, x1);
    try std.testing.expectEqual(Level.low, x2);
}

test "parse enum: 2" {
    const Level = enum(u8) {
        high = 7,
        low = 11,
    };

    const di1 = DataItem.new("\x07");
    const di2 = DataItem.new("\x0b");

    const x1 = try parse(Level, di1, .{});
    const x2 = try parse(Level, di2, .{});

    try std.testing.expectEqual(Level.high, x1);
    try std.testing.expectEqual(Level.low, x2);
}

test "serialize EcdsaP256Key" {
    const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

    const EcdsaP256Key = struct {
        /// kty:
        @"1": u8 = 2,
        /// alg:
        @"3": i8 = -7,
        /// crv:
        @"-1": u8 = 1,
        /// x-coordinate
        @"-2_b": [32]u8,
        /// y-coordinate
        @"-3_b": [32]u8,

        pub fn new(k: EcdsaP256.PublicKey) @This() {
            const xy = k.toUncompressedSec1();
            return .{
                .@"-2_b" = xy[1..33].*,
                .@"-3_b" = xy[33..65].*,
            };
        }
    };

    const k = EcdsaP256Key.new(try EcdsaP256.PublicKey.fromSec1("\x04\xd9\xf4\xc2\xa3\x52\x13\x6f\x19\xc9\xa9\x5d\xa8\x82\x4a\xb5\xcd\xc4\xd5\x63\x1e\xbc\xfd\x5b\xdb\xb0\xbf\xff\x25\x36\x09\x12\x9e\xef\x40\x4b\x88\x07\x65\x57\x60\x07\x88\x8a\x3e\xd6\xab\xff\xb4\x25\x7b\x71\x23\x55\x33\x25\xd4\x50\x61\x3c\xb5\xbc\x9a\x3a\x52"));

    const allocator = std.testing.allocator;
    var str = std.ArrayList(u8).init(allocator);
    defer str.deinit();

    try stringify(k, .{}, str.writer());

    try std.testing.expectEqualStrings("\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20\xd9\xf4\xc2\xa3\x52\x13\x6f\x19\xc9\xa9\x5d\xa8\x82\x4a\xb5\xcd\xc4\xd5\x63\x1e\xbc\xfd\x5b\xdb\xb0\xbf\xff\x25\x36\x09\x12\x9e\x22\x58\x20\xef\x40\x4b\x88\x07\x65\x57\x60\x07\x88\x8a\x3e\xd6\xab\xff\xb4\x25\x7b\x71\x23\x55\x33\x25\xd4\x50\x61\x3c\xb5\xbc\x9a\x3a\x52", str.items);
}

test "serialize tagged union: 1" {
    const AttStmtTag = enum { none };
    const AttStmt = union(AttStmtTag) {
        none: struct {},
    };

    const a = AttStmt{ .none = .{} };

    try testStringify("\xa0", a, .{});
}
