const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const cbor = @import("cbor.zig");
const parser = @import("parse.zig");

pub const Error = cbor.Error;
pub const Type = cbor.Type;
pub const DataItem = cbor.DataItem;
pub const Tag = cbor.Tag;
pub const Pair = cbor.Pair;
pub const MapIterator = cbor.MapIterator;
pub const ArrayIterator = cbor.ArrayIterator;

pub const ParseError = parser.ParseError;
pub const StringifyError = parser.StringifyError;
pub const ParseOptions = parser.ParseOptions;
pub const StringifyOptions = parser.StringifyOptions;
pub const parse = parser.parse;
pub const stringify = parser.stringify;

test {
    _ = cbor;
    _ = parser;
}
