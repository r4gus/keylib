/// PIN protocol versions
pub const PinProtocol = enum(u16) {
    /// Pin protocol version 1.
    v1 = 1,
    /// Pin Protocol version 2 for FIPS certified authenticators.
    v2 = 2,

    pub fn to_string(self: @This()) []const u8 {
        return switch (self) {
            .v1 => "V1",
            .v2 => "V2",
        };
    }
};
