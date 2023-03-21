/// Sub commands for PIN protocol
pub const SubCommand = enum(u8) {
    getPinRetries = 0x01,
    getKeyAgreement = 0x02,
    setPIN = 0x03,
    changePIN = 0x04,
    getPinToken = 0x05,
    getPinUvAuthTokenUsingUvWithPermissions = 0x06,
    getUVRetries = 0x07,
    getPinUvAuthTokenUsingPinWithPermissions = 0x09,
};
