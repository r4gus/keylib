/// Transport types
pub const Transports = enum {
    /// Indicates the respective authenticator can be contacted over removable USB.
    usb,
    /// Indicates the respective authenticator can be contacted over Near Field
    /// Communication (NFC).
    nfc,
    /// Indicates the respective authenticator can be contacted over Bluetooth Smart
    /// (Bluetooth Low Energy / BLE).
    ble,
    /// Indicates the respective authenticator is contacted using a client
    /// device-specific transport, i.e., it is a platform authenticator. These
    /// authenticators are not removable from the client device.
    internal,

    pub fn to_string(self: @This()) []const u8 {
        return switch (self) {
            .usb => "usb",
            .nfc => "nfc",
            .ble => "ble",
            .internal => "internal",
        };
    }
};
