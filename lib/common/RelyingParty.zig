//! Representation of a relying party

const cbor = @import("zbor");
const dt = @import("data_types.zig");

/// Relying party identifier
///
/// A relying party identifier is a valid domain string identifying the WebAuthn
/// Relying Party on whose behalf a given registration or authentication ceremony
/// is being performed.
///
/// TODO: 128 bytes should be enough but maybe we can also truncate the id as
/// described by the CTAP2 spec.
id: dt.ABS128T,
/// Name of the relying party
name: ?dt.ABS64T = null,

pub fn new(
    id: []const u8,
    name: ?[]const u8,
) !@This() {
    return .{
        .id = (try dt.ABS128T.fromSlice(id)).?,
        .name = try dt.ABS64T.fromSlice(name),
    };
}
