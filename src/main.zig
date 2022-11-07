/// Client to Authenticator (CTAP) library
const std = @import("std");
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const KeyPair = Ecdsa.KeyPair;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

const cbor = @import("zbor");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const DataItem = cbor.DataItem;
const Pair = cbor.Pair;

const status = @import("status.zig");
pub const StatusCodes = status.StatusCodes;
const errors = @import("error.zig");
pub const ErrorCodes = errors.ErrorCodes;
const commands = @import("commands.zig");
pub const Commands = commands.Commands;
const getCommand = commands.getCommand;
const version = @import("version.zig");
pub const Versions = version.Versions;
const extension = @import("extensions.zig");
pub const Extensions = extension.Extensions;
const option = @import("options.zig");
pub const Options = option.Options;
const pinprot = @import("pinprot.zig");
pub const PinProtocols = pinprot.PinProtocols;
const attestation_object = @import("attestation_object.zig");

pub const ms_length = Hmac.mac_length;

pub fn Auth(comptime impl: type) type {
    return struct {
        const Self = @This();

        /// List of supported versions.
        versions: []const Versions,
        /// List of supported extensions.
        extensions: ?[]const Extensions,
        /// The Authenticator Attestation GUID (AAGUID) is a 128-bit identifier
        /// indicating the type of the authenticator. Authenticators with the
        /// same capabilities and firmware, can share the same AAGUID.
        aaguid: [16]u8,
        /// Supported options.
        options: ?Options,
        /// Maximum message size supported by the authenticator.
        /// null = unlimited.
        max_msg_size: ?u64,
        /// List of supported PIN Protocol versions.
        pin_protocols: ?[]const u8,

        /// Default initialization without extensions.
        pub fn initDefault(versions: []const Versions, aaguid: [16]u8) Self {
            return @This(){
                .versions = versions,
                .extensions = null,
                .aaguid = aaguid,
                .options = Options.default(),
                .max_msg_size = null,
                .pin_protocols = null,
            };
        }

        pub const crypto = struct {
            const key_len: usize = 32;
            const ctx_len: usize = 32;

            pub const KeyContext = struct {
                /// Context which serves as KEYID and is stored
                /// by the RP.
                ctx: [ctx_len]u8,
                /// Key-Pair derived from the context and the
                /// master secret. The private key must be kept
                /// secret. The public key is stored by the
                /// RP.
                key_pair: KeyPair,
            };

            /// Get a 32 bit random number.
            pub fn rand() u32 {
                return impl.rand();
            }

            /// Fill the given slice with random data.
            pub fn getBlock(buffer: []u8) void {
                var r: u32 = undefined;

                var i: usize = 0;
                while (i < buffer.len) : (i += 1) {
                    if (i % 4 == 0) {
                        // Get a fresh 32 bit integer every 4th iteration.
                        r = rand();
                    }

                    // The shift value is always between 0 and 24, i.e. int cast will always succeed.
                    buffer[i] = @intCast(u8, (r >> @intCast(u5, (8 * (i % 4)))) & 0xff);
                }
            }

            /// Get the stored master secret.
            ///
            /// The master secret must be created on first boot, i.e.
            /// one can expect the master secret to be available at
            /// any time.
            pub fn getMs() [ms_length]u8 {
                return impl.getMs();
            }

            /// Create and store a new master secret.
            ///
            /// This function has to be called once on first boot
            /// to create the secret. The master secret must not
            /// change between power cycles. Changing the secret
            /// means invalidating all generated key pairs, which
            /// is equivalent to a reset.
            pub fn createMs() void {
                impl.createMs();
            }

            pub fn createKeyPair() !KeyContext {
                // Get new random context for new key pair
                var ctx: [ctx_len]u8 = undefined;
                getBlock(ctx[0..]);

                // Derive subkey (seed) from master secret and ctx
                var seed: [key_len]u8 = undefined;
                Hkdf.expand(seed[0..], ctx[0..], getMs());

                // Create a new (deterministic) key pair
                const kc = KeyContext{
                    .ctx = ctx,
                    .key_pair = try KeyPair.create(seed),
                };

                return kc;
            }

            pub fn deriveKeyPair(ctx: [ctx_len]u8) !KeyPair {
                var seed: [key_len]u8 = undefined;
                Hkdf.expand(seed[0..], ctx[0..], getMs());
                return try KeyPair.create(seed);
            }
        };

        /// Main handler function, that takes a command and returns a response.
        pub fn handle(self: *const Self, allocator: Allocator, command: []const u8) ![]u8 {
            // The response message.
            // For encodings see: https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#responses
            var res = std.ArrayList(u8).init(allocator);
            var response = res.writer();

            const cmdnr = getCommand(command) catch |err| {
                // On error, respond with a error code and return.
                try response.writeByte(@enumToInt(StatusCodes.fromError(err)));
                return res.toOwnedSlice();
            };

            switch (cmdnr) {
                .authenticator_make_credential => {
                    const di = DataItem.int(@intCast(i65, crypto.rand()));

                    try response.writeByte(0x00);
                    try cbor.encode(response, &di);
                },
                .authenticator_get_assertion => {},
                .authenticator_get_info => {
                    // There is a maximum of 6 supported members (including optional ones).
                    var members = std.ArrayList(Pair).init(allocator);
                    var i: usize = 0;

                    // versions (0x01)
                    var versions = try allocator.alloc(DataItem, self.versions.len);
                    for (self.versions) |vers| {
                        versions[i] = try DataItem.text(allocator, vers.toString());
                        i += 1;
                    }
                    try members.append(Pair.new(DataItem.int(0x01), DataItem{ .array = versions }));

                    // extensions (0x02)
                    if (self.extensions != null) {
                        var extensions = try allocator.alloc(DataItem, self.extensions.?.len);

                        i = 0;
                        for (self.extensions.?) |ext| {
                            extensions[i] = try DataItem.text(allocator, ext.toString());
                            i += 1;
                        }
                        try members.append(Pair.new(DataItem.int(0x02), DataItem{ .array = extensions }));
                    }

                    // aaguid (0x03)
                    try members.append(Pair.new(DataItem.int(0x03), try DataItem.bytes(allocator, &self.aaguid)));

                    // options (0x04)
                    if (self.options != null) {
                        var options = std.ArrayList(Pair).init(allocator);

                        try options.append(Pair.new(try DataItem.text(allocator, "rk"), if (self.options.?.rk) DataItem.True() else DataItem.False()));
                        try options.append(Pair.new(try DataItem.text(allocator, "up"), if (self.options.?.up) DataItem.True() else DataItem.False()));
                        if (self.options.?.uv != null) {
                            try options.append(Pair.new(try DataItem.text(allocator, "uv"), if (self.options.?.uv.?) DataItem.True() else DataItem.False()));
                        }
                        try options.append(Pair.new(try DataItem.text(allocator, "plat"), if (self.options.?.plat) DataItem.True() else DataItem.False()));
                        if (self.options.?.client_pin != null) {
                            try options.append(Pair.new(try DataItem.text(allocator, "clienPin"), if (self.options.?.client_pin.?) DataItem.True() else DataItem.False()));
                        }

                        try members.append(Pair.new(DataItem.int(0x04), DataItem{ .map = options.toOwnedSlice() }));
                    }

                    // maxMsgSize (0x05)
                    if (self.max_msg_size != null) {
                        try members.append(Pair.new(DataItem.int(0x05), DataItem.int(self.max_msg_size.?)));
                    }

                    // pinProtocols (0x06)
                    if (self.pin_protocols != null) {
                        var protocols = try allocator.alloc(DataItem, self.extensions.?.len);

                        i = 0;
                        for (self.pin_protocols.?) |prot| {
                            protocols[i] = DataItem.int(prot);
                            i += 1;
                        }
                        try members.append(Pair.new(DataItem.int(0x06), DataItem{ .array = protocols }));
                    }

                    var di = DataItem{ .map = members.toOwnedSlice() };
                    defer di.deinit(allocator);

                    try response.writeByte(0x00);
                    try cbor.encode(response, &di);
                },
                .authenticator_client_pin => {},
                .authenticator_reset => {},
                .authenticator_get_next_assertion => {},
                .authenticator_vendor_first => {},
                .authenticator_vendor_last => {},
            }

            return res.toOwnedSlice();
        }
    };
}

const tests = @import("tests.zig");

test "main" {
    _ = tests;
    _ = attestation_object;
}
