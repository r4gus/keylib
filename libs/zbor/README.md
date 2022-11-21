# zbor - Zig CBOR

![GitHub](https://img.shields.io/github/license/r4gus/zbor?style=flat-square)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/r4gus/zbor/CI?style=flat-square)
![GitHub all releases](https://img.shields.io/github/downloads/r4gus/zbor/total?style=flat-square)

The Concise Binary Object Representation (CBOR) is a data format whose design 
goals include the possibility of extremely small code size, fairly small 
message size, and extensibility without the need for version negotiation
([RFC8949](https://www.rfc-editor.org/rfc/rfc8949.html#abstract)). It is used
in different protocols like [CTAP](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form) 
and [WebAuthn](https://www.w3.org/TR/webauthn-2/#cbor) (FIDO2).

## Getting started

To use this library in your own project just add it as a submodule, e.g.:

```
your-project$ mkdir libs
your-project$ git submodule add https://github.com/r4gus/zbor.git libs/zbor
```

Then add the following line to your `build.zig` file.

```zig
exe.addPackagePath("zbor", "libs/zbor/src/main.zig");
```

## Usage

This library lets you inspect and parse CBOR data without having to allocate
additional memory.

> Note: This library is not mature and probably still has bugs. If you encounter
> any errors please open an [issue](https://github.com/r4gus/zbor/issues/new).

### Inspect CBOR data

To inspect CBOR data you must first create a new `DataItem`.

```zig
const cbor = @import("zbor");

const di = DataItem.new("\x1b\xff\xff\xff\xff\xff\xff\xff\xff");
```

To check the type of the given `DataItem` use the `getType()` function.

```zig
std.debug.assert(di.getType() == .Int);
```

Possible types include `Int` (major type 0 and 1) `ByteString` (major type 2), `TextString` (major type 3), `Array` (major type 4), `Map` (major type 5), `Tagged` (major type 6) and `Float` (major type 7).

Based on the given type you can the access the underlying value.

```zig
std.debug.assert(di.int().? == 18446744073709551615);
```

All getter functions return either a value or `null`. You can use a pattern like `if (di.int()) |v| v else return error.Oops;` to access the value in a safe way.

> The CBOR data is only parsed if you call one of the `DataItem` functions
> and only as far as necessary.

The following getter functions are supported:
* `int` - returns `?i65`
* `string` - returns `?[]const u8`
* `array` - returns `?ArrayIterator`
* `map` - returns `?MapIterator`
* `simple` - returns `?u8`
* `float` - returns `?f64`
* `tagged` - returns `?Tag`

#### Iterators

The functions `array` and `map` will return an iterator. Every time you
call `next()` you will either get a `DataItem`/ `Pair` or `null`.

```zig
const di = DataItem.new("\x98\x19\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x18\x18\x19");

var iter = di.array().?;
while (iter.next()) |value| {
  _ = value;
  // doe something
}
```

### Serialization

You can serialize Zig objects into CBOR using the `stringify()` function.

```zig
const allocator = std.testing.allocator;
var str = std.ArrayList(u8).init(allocator);
defer str.deinit();

const Info = struct {
    versions: []const []const u8,
};

const i = Info{
    .versions = &.{"FIDO_2_0"},
};

try stringify(i, .{}, str.writer());
```


You can deserialize CBOR data into Zig objects using the `parse()` function.

```zig
const e = [5]u8{ 1, 2, 3, 4, 5 };
const di = DataItem.new("\x85\x01\x02\x03\x04\x05");

const x = try parse([5]u8, di, .{});

try std.testing.expectEqualSlices(u8, e[0..], x[0..]);
```

The parser might require an allocator, which you can provide with `.{.allocator = <your allocator>}`.
You're responsible for freeing all allocated memory!

#### Field names

If you want to serialize a specific field of a struct as byte string use the `_b` postfix for your field
name, e.g. `struct { id_b: []const u8 }`. You can also use `_t` for text strings. The postfix will be
ignored by the serializer.
