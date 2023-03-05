/// PIN protocol versions
pub const PinProtocol = enum(u16) {
    /// Pin protocol version 1.
    v1 = 1,
    /// Pin Protocol version 2 for FIPS certified authenticators.
    v2 = 2,
};
