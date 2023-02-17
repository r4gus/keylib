//! Authenticator options.
//!
//! When an option is not present, the default is applied.
//!
//! https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#authenticatorGetInfo

/// present + true: enterprise attestation supported and enabled
/// present + false: enterprise attestation supported but disabled
/// absent: enterprise attestation not supported
ep: ?bool = null,
/// Resident key: Indicates that the device is capable of storing keys on
/// the device itself and therefore can satisfy the `authenticatorGetAssertion`
/// request with `allowList` parameter not specified or empty.
rk: bool = false,
/// User presence.
/// true: indicates that the device is capable of testing user presence.
up: bool = true,
/// User verification: Device is capable of verifiying the user within itself.
/// present + true: device is capable of user verification within itself and
///                 has been configured.
/// present + false: device is capable of user verification within itself and
///                  has not been yet configured.
/// absent: device is not capable of user verification within itself.
///
/// A device that can only do Client PIN will not return the "uv" parameter.
uv: ?bool = null,
/// Platform device: Indicates that the device is attached to the client
/// and therefore can't be removed and used on another client.
plat: bool = false,
/// authenticatorConfig command is supported Y/n
authnrCfg: ?bool = null,
/// present + true: device is capable of accepting a PIN from the client and
///                 PIN has been set
/// present + false: device is capable of accepting a PIN from the client and
///                  PIN has not been set yet.
/// absent: indicates that the device is not capable of accepting a PIN from the client.
clientPin: ?bool = null,
/// Authenticator supports largeBlobs Y/n
largeBlobs: ?bool = null,
/// present + true:             the authenticator supports authenticatorClientPIN's 
///                             getPinUvAuthTokenUsingPinWithPermissions subcommand.
///                             If the uv option id is present and set to true, then 
///                             the authenticator supports authenticatorClientPIN's 
///                             getPinUvAuthTokenUsingUvWithPermissions subcommand.
/// present + false or absent:  the authenticator does not support authenticatorClientPIN's 
///                             getPinUvAuthTokenUsingPinWithPermissions and 
///                             getPinUvAuthTokenUsingUvWithPermissions subcommands.
pinUvAuthToken: ?bool = null,
/// present + true:             pinUvAuthToken not allowd for credential creation and assertion
/// present + false or absetn:  can be used for credential creation and assertion
noMcGaPermissionsWithClientPin: bool = false,

// TODO: support remaining options