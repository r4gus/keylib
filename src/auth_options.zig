pub const AuthenticatorOptions = struct {
    /// user presence: Instructs the authenticator to require user consent to
    /// complete the operation.
    up: bool = true,
    /// resident key: Instructs the authenticator to store the key material on the device.
    rk: bool = false,
    /// user verification: Instructs the authenticator to require a gesture that
    /// verifies the user to complete the request. Examples of such gestures
    /// are fingerprint scan or a PIN.
    uv: bool = false,
};
