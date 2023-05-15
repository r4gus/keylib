/// This enumeration defines hints as to how clients might communicate with a
/// particular authenticator in order to obtain an assertion for a specific credential
pub const AuthenticatorTransports = enum {
    /// Indicates the respective authenticator can be contacted over removable USB
    usb,
    /// Indicates the respective authenticator can be contacted over Near Field
    /// Communication (NFC)
    nfc,
    /// Indicates the respective authenticator can be contacted over Bluetooth
    /// Smart (Bluetooth Low Energy / BLE)
    ble,
    /// Indicates the respective authenticator can be contacted over ISO/IEC 7816
    /// smart card with contacts
    @"smart-card",
    /// Indicates the respective authenticator can be contacted using a
    /// combination of (often separate) data-transport and proximity mechanisms.
    /// This supports, for example, authentication on a desktop computer using a
    /// smartphone.
    hybrid,
    /// Indicates the respective authenticator is contacted using a client
    /// device-specific transport, i.e., it is a platform authenticator.
    /// These authenticators are not removable from the client device.
    internal,
};
