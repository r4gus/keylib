//! This is a template for implementing your own FIDO2 authenticator based on keylib.
//!
//! While this library allows you to implement a authenticator quite
//! easily as seen below you can also just use the data structures and build one
//! from scratch yourself.

const std = @import("std");
const keylib = @import("keylib");
const cbor = @import("zbor");
const uhid = @import("uhid");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

pub fn main() !void {
    // a static credential to work with
    try data_set.append(.{
        .id = "\xb4\x40\xa4\xed\x80\x92\xe6\x9b\x19\x25\x2d\x25\x84\xc2\xa4\xce\x56\x38\x66\xd6\x4d\xb3\x13\x4e\x48\xd6\x1b\xc2\xb9\x32\xae\x23",
        .rp = "trust-anchor.testbed.oidcfed.incubator.geant.org",
        .data = "A96269645820B440A4ED8092E69B19252D2584C2A4CE563866D64DB3134E48D61BC2B932AE236475736572A26269644C0C430EFFFF5F5F5F44454D4F646E616D6565657277696E627270A1626964783074727573742D616E63686F722E746573746265642E6F6964636665642E696E63756261746F722E6765616E742E6F72676A7369676E5F636F756E740063616C676545733235366B707269766174655F6B657958201BA2453ED863B547C93AE1B2244459F2E403FC8E951B15F458335DFB3C80397467637265617465641B0000018D75C3FDC86C646973636F76657261626C65F56A657874656E73696F6E7382A26565787449644B6372656450726F746563746865787456616C7565581875736572566572696669636174696F6E4F7074696F6E616CA26565787449644569647049646865787456616C7565584168747470733A2F2F74727573742D616E63686F722E746573746265642E6F6964636665642E696E63756261746F722E6765616E742E6F72672F6F6964632F6F702F",
    });

    // The Auth struct is the most important part of your authenticator. It defines
    // its capabilities and behavior.
    var auth = keylib.ctap.authenticator.Auth{
        // The callbacks are the interface between the authenticator and the rest of the application (see below).
        .callbacks = callbacks,
        // The commands map from a command code to a command function. All functions have the
        // same interface and you can implement your own to extend the authenticator beyond
        // the official spec, e.g. add a command to store passwords.
        .commands = &.{
            .{ .cmd = 0x01, .cb = keylib.ctap.commands.authenticator.authenticatorMakeCredential },
            .{ .cmd = 0x02, .cb = keylib.ctap.commands.authenticator.authenticatorGetAssertion },
            .{ .cmd = 0x04, .cb = keylib.ctap.commands.authenticator.authenticatorGetInfo },
            .{ .cmd = 0x06, .cb = keylib.ctap.commands.authenticator.authenticatorClientPin },
            .{ .cmd = 0x0b, .cb = keylib.ctap.commands.authenticator.authenticatorSelection },
        },
        // The settings are returned by a getInfo request and describe the capabilities
        // of your authenticator. Make sure your configuration is valid based on the
        // CTAP2 spec!
        .settings = .{
            // Those are the FIDO2 spec you support
            .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
            // The extensions are defined as strings which should make it easy to extend
            // the authenticator (in combination with a new command).
            .extensions = &.{ "credProtect", "federationId" },
            // This should be unique for all models of the same authenticator.
            .aaguid = "\x6f\x15\x82\x74\xaa\xb6\x44\x3d\x9b\xcf\x8a\x3f\x69\x29\x7c\x88".*,
            .options = .{
                // We don't support the credential management command. If you want to
                // then you need to implement it yourself and add it to commands and
                // set this flag to true.
                .credMgmt = false,
                // We support discoverable credentials, a.k.a resident keys, a.k.a passkeys
                .rk = true,
                // We support built in user verification (see the callback below)
                .uv = true,
                // This is a platform authenticator even if we use usb for ipc
                .plat = true,
                // We don't support client pin but you could also add the command
                // yourself and set this to false (not initialized) or true (initialized).
                .clientPin = null,
                // We support pinUvAuthToken
                .pinUvAuthToken = true,
                // If you want to enforce alwaysUv you also have to set this to true.
                .alwaysUv = false,
            },
            // The pinUvAuth protocol to support. This library implements V1 and V2.
            .pinUvAuthProtocols = &.{.V2},
            // The transports your authenticator supports.
            .transports = &.{.usb},
            // The algorithms you support.
            .algorithms = &.{.{ .alg = .Es256 }},
            .firmwareVersion = 0xcafe,
            .remainingDiscoverableCredentials = 100,
        },
        // Here we initialize the pinUvAuth token data structure wich handles the generation
        // and management of pinUvAuthTokens.
        .token = keylib.ctap.pinuv.PinUvAuth.v2(std.crypto.random),
        // Here we set the supported algorithm. You can also implement your
        // own and add them here.
        .algorithms = &.{
            keylib.ctap.crypto.algorithms.Es256,
        },
        // This allocator is used to allocate memory and has to be the same
        // used for the callbacks.
        .allocator = allocator,
        // A function to get the epoch time as i64.
        .milliTimestamp = std.time.milliTimestamp,
        // A cryptographically secure random number generator
        .random = std.crypto.random,
        // If you don't want to increment the sign counts
        // of credentials (e.g. because you sync them between devices)
        // set this to true.
        .constSignCount = true,
    };
    try auth.init();

    // Here we instantiate a CTAPHID handler.
    var ctaphid = keylib.ctap.transports.ctaphid.authenticator.CtapHid.init(allocator, std.crypto.random);
    defer ctaphid.deinit();

    // We use the uhid module on linux to simulate a USB device. If you use
    // tinyusb or something similar you have to adapt the code.
    var u = try uhid.Uhid.open();
    defer u.close();

    // This is the main loop
    while (true) {
        // We read in usb packets with a size of 64 bytes.
        var buffer: [64]u8 = .{0} ** 64;
        if (u.read(&buffer)) |packet| {
            // Those packets are passed to the CTAPHID handler who assembles
            // them into a CTAPHID message.
            var response = ctaphid.handle(packet);
            // Once a message is complete (or an error has occured) you
            // get a response.
            if (response) |*res| blk: {
                switch (res.cmd) {
                    // Here we check if its a cbor message and if so, pass
                    // it to the handle() function of our authenticator.
                    .cbor => {
                        var out: [7609]u8 = undefined;
                        const r = auth.handle(&out, res.getData());
                        std.mem.copy(u8, res._data[0..r.len], r);
                        res.len = r.len;
                    },
                    else => {},
                }

                var iter = res.iterator();
                // Here we iterate over the response packets of our authenticator.
                while (iter.next()) |p| {
                    u.write(p) catch {
                        break :blk;
                    };
                }
            }
        }
        std.time.sleep(10000000);
    }
}

// /////////////////////////////////////////
// Data
// /////////////////////////////////////////

const Data = struct {
    rp: []const u8,
    id: []const u8,
    data: []const u8,
};

// For this example we use a volatile storage solution for our credentials.
var data_set = std.ArrayList(Data).init(allocator);

// /////////////////////////////////////////
// Auth
//
// Below you can see all the callbacks you have to implement
// (that are expected by the default command functions). Make
// sure you allocate memory with the same allocator that you
// passed to the Auth sturct.
//
// How you check user presence, conduct user verification or
// store the credentials is up to you.
// /////////////////////////////////////////

const UpResult = keylib.ctap.authenticator.callbacks.UpResult;
const UvResult = keylib.ctap.authenticator.callbacks.UvResult;
const Error = keylib.ctap.authenticator.callbacks.Error;

pub fn my_uv(
    /// Information about the context (e.g., make credential)
    info: [*c]const u8,
    /// Information about the user (e.g., `David Sugar (david@example.com)`)
    user: [*c]const u8,
    /// Information about the relying party (e.g., `Github (github.com)`)
    rp: [*c]const u8,
) callconv(.C) UvResult {
    _ = info;
    _ = user;
    _ = rp;
    // The authenticator backend is only started if a correct password has been provided
    // so we return Accepted. As this state may last for multiple minutes it's important
    // that we ask for user presence, i.e. we DONT return AcceptedWithUp!
    //
    // TODO: "logout after being inactive for m minutes"
    return UvResult.Accepted;
}

pub fn my_up(
    /// Information about the context (e.g., make credential)
    info: [*c]const u8,
    /// Information about the user (e.g., `David Sugar (david@example.com)`)
    user: [*c]const u8,
    /// Information about the relying party (e.g., `Github (github.com)`)
    rp: [*c]const u8,
) callconv(.C) UpResult {
    _ = info;
    _ = user;
    _ = rp;

    return UpResult.Accepted;
}

pub fn my_select(
    rpId: [*c]const u8,
    users: [*c][*c]const u8,
) callconv(.C) i32 {
    _ = rpId;
    _ = users;

    return 0;
}

pub fn my_read(
    id: [*c]const u8,
    rp: [*c]const u8,
    out: *[*c][*c]u8,
) callconv(.C) Error {
    var entries = std.ArrayList([*c]u8).init(allocator);

    if (id != null) {
        // get the one with the id
        const id_ = id[0..strlen(id)];

        for (data_set.items) |*entry| {
            if (std.mem.eql(u8, entry.id, id_)) {
                const d = allocator.dupeZ(u8, entry.data) catch {
                    entries.deinit();
                    return Error.OutOfMemory;
                };

                entries.append(d) catch unreachable;
                entries.append(null) catch unreachable;
                const o = entries.toOwnedSlice() catch unreachable;
                out.* = o.ptr;
                return Error.SUCCESS;
            }
        }

        entries.deinit();
        return Error.DoesNotExist;
    } else if (rp != null) {
        // get all associated with id
        const rp_ = rp[0..strlen(rp)];

        for (data_set.items) |*entry| {
            if (std.mem.eql(u8, entry.rp, rp_)) {
                const d = allocator.dupeZ(u8, entry.data) catch {
                    entries.deinit();
                    return Error.OutOfMemory;
                };

                entries.append(d) catch unreachable;
            }
        }

        if (entries.items.len > 0) {
            entries.append(null) catch unreachable;
            const o = entries.toOwnedSlice() catch unreachable;
            out.* = o.ptr;
            return Error.SUCCESS;
        }

        entries.deinit();
        return Error.DoesNotExist;
    } else {
        // get all
        for (data_set.items) |*entry| {
            if (!std.mem.eql(u8, entry.rp, "Root")) {
                const d = allocator.dupeZ(u8, entry.data) catch {
                    entries.deinit();
                    return Error.OutOfMemory;
                };

                entries.append(d) catch unreachable;
            }
        }

        if (entries.items.len > 0) {
            entries.append(null) catch unreachable;
            const o = entries.toOwnedSlice() catch unreachable;
            out.* = o.ptr;
            return Error.SUCCESS;
        }

        entries.deinit();
        return Error.DoesNotExist;
    }

    return Error.DoesNotExist;
}

pub fn my_write(
    id: [*c]const u8,
    rp: [*c]const u8,
    data: [*c]const u8,
) callconv(.C) Error {
    if (id == null or rp == null or data == null) {
        return Error.Other;
    }

    const id_ = id[0..strlen(id)];
    const rp_ = rp[0..strlen(rp)];
    const data_ = data[0..strlen(data)];

    for (data_set.items) |*entry| {
        if (std.mem.eql(u8, entry.id, id_)) {
            allocator.free(entry.data);
            entry.data = allocator.dupe(u8, data_) catch {
                // TODO: here we should actually free the entry as the data is invalid
                return Error.OutOfMemory;
            };
            return Error.SUCCESS;
        }
    }

    const id2 = allocator.dupe(u8, id_) catch {
        return Error.OutOfMemory;
    };
    const rp2 = allocator.dupe(u8, rp_) catch {
        allocator.free(id2);
        return Error.OutOfMemory;
    };
    const data2 = allocator.dupe(u8, data_) catch {
        allocator.free(id2);
        allocator.free(rp2);
        return Error.OutOfMemory;
    };

    data_set.append(Data{
        .rp = rp2,
        .id = id2,
        .data = data2,
    }) catch {
        allocator.free(id2);
        allocator.free(rp2);
        allocator.free(data2);
        return Error.OutOfMemory;
    };

    return Error.SUCCESS;
}

pub fn my_delete(
    id: [*c]const u8,
) callconv(.C) Error {
    _ = id;
    return Error.Other;
}

const callbacks = keylib.ctap.authenticator.callbacks.Callbacks{
    .up = my_up,
    .uv = my_uv,
    .select = my_select,
    .read = my_read,
    .write = my_write,
    .delete = my_delete,
};

// MISC

pub fn strlen(s: [*c]const u8) usize {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {}
    return i;
}
