/// Authenticator options.
///
/// When an option is not present, the default is applied.
pub const Options = struct {
    /// Platform device: Indicates that the device is attached to the client
    /// and therefore can't be removed and used on another client.
    plat: bool,
    /// Resident key: Indicates that the device is capable of storing keys on
    /// the device itself and therefore can satisfy the `authenticatorGetAssertion`
    /// request with `allowList` parameter not specified or empty.
    rk: bool,
    /// present + true: device is capable of accepting a PIN from the client and
    ///                 PIN has been set
    /// present + false: device is capable of accepting a PIN from the client and
    ///                  PIN has not been set yet.
    /// absent: indicates that the device is not capable of accepting a PIN from the client.
    client_pin: ?bool,
    /// User presence.
    /// true: indicates that the device is capable of testing user presence.
    up: bool,
    /// User verification: Device is capable of verifiying the user within itself.
    /// present + true: device is capable of user verification within itself and
    ///                 has been configured.
    /// present + false: device is capable of user verification within itself and
    ///                  has not been yet configured.
    /// absent: device is not capable of user verification within itself.
    ///
    /// A device that can only do Client PIN will not return the "uv" parameter.
    uv: ?bool,

    pub fn default() @This() {
        return @This(){
            .plat = false,
            .rk = false,
            .client_pin = null,
            .up = true,
            .uv = null,
        };
    }
};
