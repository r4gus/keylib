/// CTAP status codes.
pub const StatusCodes = enum(u8) {
    /// Indicates successful response.
    ctap1_err_success = 0x00,
    /// The command is not a valid CTAP command.
    ctap1_err_invalid_command = 0x01,
    /// The command included an invalid parameter.
    ctap1_err_invalid_parameter = 0x02,
    /// Invalid message or item length.
    ctap1_err_invalid_length = 0x03,
    /// Invalid message sequencing.
    ctap1_err_invalid_seq = 0x04,
    /// Message timed out.
    ctap1_err_tiemout = 0x05,
    /// Channel busy.
    ctap1_err_channel_busy = 0x06,
    /// Command requires channel lock.
    ctap1_err_lock_required = 0x0a,
    /// Command not allowed on this cid.
    ctap1_err_invalid_channel = 0x0b,
    /// Invalid/ unexpected CBOR error.
    ctap2_err_cbor_unexpected_type = 0x11,
    /// Error when parsing CBOR.
    ctap2_err_invalid_cbor = 0x12,
    /// Missing non-optional parameter.
    ctap2_err_missing_parameter = 0x14,
    /// Limit for number of items exceeded.
    ctap2_err_limit_exceeded = 0x15,
    /// Unsupported extension.
    ctap2_err_unsupported_extension = 0x16,
    /// Valid credential found in the excluded list.
    ctap2_err_credential_excluded = 0x19,
    /// Processing (Lenghty operation is in progress).
    ctap2_err_processing = 0x21,
    /// Credential not valid for the authenticator.
    ctap2_err_invalid_credential = 0x22,
    /// Authenticator is waiting for user interaction.
    ctap2_err_user_action_pending = 0x23,
    /// Processing, lengthy operation is in progress.
    ctap2_err_operation_pending = 0x24,
    /// No request is pending.
    ctap2_err_no_operations = 0x25,
    /// Authenticator does not support requested algorithm.
    ctap2_err_unsupported_algorithm = 0x26,
    /// Not authorized for requested operation.
    ctap2_err_operation_denied = 0x27,
    /// Internal key storage is full.
    ctap2_err_key_store_full = 0x28,
    /// Authenticator cannot cancel as it is not busy.
    ctap2_err_not_busy = 0x29,
    /// No outstanding operations.
    ctap2_err_no_operation_pending = 0x2a,
    /// Unsupported option.
    ctap2_err_unsupported_option = 0x2b,
    /// Not a valid option for current operation.
    ctap2_err_invalid_option = 0x2c,
    /// Pending keep alive was canceled.
    ctap2_err_keepalive_cancel = 0x2d,
    /// No valid credentials provided.
    ctap2_err_no_credentials = 0x2e,
    /// Timeout waiting for user interaction.
    ctap2_err_user_action_timeout = 0x2f,
    /// Continuation command, such as, `authenticatorGetNexAssertion` not allowed.
    ctap2_err_not_allowed = 0x30,
    /// PIN invalid.
    ctap2_err_pin_invalid = 0x31,
    /// PIN blocked.
    ctap2_err_pin_blocked = 0x32,
    /// PIN authentication (`pinAuth`) verification failed.
    ctap2_err_pin_auth_invalid = 0x33,
    /// PIN authentication (`pinAuth`) blocked. Requires power recycle to reset.
    ctap2_err_pin_auth_blocked = 0x34,
    /// No PIN has been set.
    ctap2_err_pin_not_set = 0x35,
    /// PIN is required for the selected operation.
    ctap2_err_pin_required = 0x36,
    /// PIN policy violation. Currently only enforces minimum length.
    ctap2_err_pin_policy_violation = 0x37,
    /// `pinToken` expired on authenticator.
    ctap2_err_pin_token_expired = 0x38,
    /// Authenticator cannot handle this request due to memory constraints.
    ctap2_err_request_too_large = 0x39,
    /// The current operation has timed out.
    ctap2_err_action_timeout = 0x3a,
    /// User presence is required for the requested operation.
    ctap2_err_up_required = 0x3b,
    /// built-in user verification is disabled.
    ctap2_err_uv_blocked = 0x3c,
    /// A checksum did not match.
    ctap2_err_integrity_failure = 0x3d,
    /// The requested subcommand is either invalid or not implemented.
    ctap2_err_invalid_subcommand = 0x3e,
    /// built-in user verification unsuccessful. The platform SHOULD retry.
    ctap2_err_uv_invalid = 0x3f,
    /// The permissions parameter contains an unauthorized permission.
    ctap2_err_unauthorized_permission = 0x40,
    /// Other unspecified error.
    ctap1_err_other = 0x7f,
    /// CTAP 2 spac last error.
    ctap2_err_spec_last = 0xdf,
    /// Extension specific error.
    ctap2_err_extension_first = 0xe0,
    /// Extension specific error.
    ctap2_err_extension_last = 0xef,
    /// Vendor specific error.
    ctap2_err_vendor_first = 0xf0,
    /// Vendor specific error.
    ctap2_err_vendor_last = 0xff,
};
