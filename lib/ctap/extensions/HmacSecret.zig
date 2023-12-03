const cbor = @import("zbor");
const fido = @import("../../main.zig");

pub const HmacSecretTag = enum { create, get, output };

pub const HmacSecret = union(HmacSecretTag) {
    create: bool,
    get: struct {
        /// Public key of platform key-agreement key (also used by pinUv protocol)
        keyAgreement: cbor.cose.Key,
        /// Encryption of the one or two salts (called salt1 (32 bytes) and salt2 (32 bytes))
        /// using the shared secret as follows:
        ///     One salt case: encrypt(shared secret, salt1)
        ///     Two salt case: encrypt(shared secret, salt1 || salt2)
        saltEnc: []const u8,
        /// authenticate(shared secret, saltEnc)
        saltAuth: []const u8,
        /// As selected when getting the shared secret. CTAP2.1 platforms MUST include this
        /// parameter if the value of pinUvAuthProtocol is not 1.
        pinUvAuthProtocol: ?fido.ctap.pinuv.common.PinProtocol = null,
    },
    output: []const u8,

    pub fn cborStringify(self: *const @This(), options: cbor.Options, out: anytype) !void {
        _ = options;

        try cbor.stringify(self.*, .{
            .field_settings = &.{
                .{ .name = "keyAgreement", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
                .{ .name = "saltEnc", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "saltAuth", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
                .{ .name = "pinUvAuthProtocol", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
            },
            .from_callback = true,
        }, out);
    }

    pub fn cborParse(item: cbor.DataItem, options: cbor.Options) !@This() {
        return try cbor.parse(@This(), item, .{
            .allocator = options.allocator,
            .field_settings = &.{
                .{ .name = "keyAgreement", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
                .{ .name = "saltEnc", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "saltAuth", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
                .{ .name = "pinUvAuthProtocol", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
            },
            .from_callback = true,
        });
    }
};
