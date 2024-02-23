pub const StatusCodes = error{
    /// The command is not a valid CTAP command.
    ctap1_err_invalid_command,
    /// The command included an invalid parameter.
    ctap1_err_invalid_parameter,
    /// Invalid message or item length.
    ctap1_err_invalid_length,
    /// Invalid message sequencing.
    ctap1_err_invalid_seq,
    /// Message timed out.
    ctap1_err_timeout,
    /// Channel busy.
    ctap1_err_channel_busy,
    /// Command requires channel lock.
    ctap1_err_lock_required,
    /// Command not allowed on this cid.
    ctap1_err_invalid_channel,
    /// Invalid/ unexpected CBOR error.
    ctap2_err_cbor_unexpected_type,
    /// Error when parsing CBOR.
    ctap2_err_invalid_cbor,
    /// Missing non-optional parameter.
    ctap2_err_missing_parameter,
    /// Limit for number of items exceeded.
    ctap2_err_limit_exceeded,
    /// Unsupported extension.
    ctap2_err_unsupported_extension,
    /// Valid credential found in the excluded list.
    ctap2_err_credential_excluded,
    /// Processing (Lenghty operation is in progress).
    ctap2_err_processing,
    /// Credential not valid for the authenticator.
    ctap2_err_invalid_credential,
    /// Authenticator is waiting for user interaction.
    ctap2_err_user_action_pending,
    /// Processing, lengthy operation is in progress.
    ctap2_err_operation_pending,
    /// No request is pending.
    ctap2_err_no_operations,
    /// Authenticator does not support requested algorithm.
    ctap2_err_unsupported_algorithm,
    /// Not authorized for requested operation.
    ctap2_err_operation_denied,
    /// Internal key storage is full.
    ctap2_err_key_store_full,
    /// Authenticator cannot cancel as it is not busy.
    ctap2_err_not_busy,
    /// No outstanding operations.
    ctap2_err_no_operation_pending,
    /// Unsupported option.
    ctap2_err_unsupported_option,
    /// Not a valid option for current operation.
    ctap2_err_invalid_option,
    /// Pending keep alive was canceled.
    ctap2_err_keepalive_cancel,
    /// No valid credentials provided.
    ctap2_err_no_credentials,
    /// Timeout waiting for user interaction.
    ctap2_err_user_action_timeout,
    /// Continuation command, such as, `authenticatorGetNexAssertion` not allowed.
    ctap2_err_not_allowed,
    /// PIN invalid.
    ctap2_err_pin_invalid,
    /// PIN blocked.
    ctap2_err_pin_blocked,
    /// PIN authentication (`pinAuth`) verification failed.
    ctap2_err_pin_auth_invalid,
    /// PIN authentication (`pinAuth`) blocked. Requires power recycle to reset.
    ctap2_err_pin_auth_blocked,
    /// No PIN has been set.
    ctap2_err_pin_not_set,
    /// PIN is required for the selected operation.
    ctap2_err_pin_required,
    /// PIN policy violation. Currently only enforces minimum length.
    ctap2_err_pin_policy_violation,
    /// `pinToken` expired on authenticator.
    ctap2_err_pin_token_expired,
    /// Authenticator cannot handle this request due to memory constraints.
    ctap2_err_request_too_large,
    /// The current operation has timed out.
    ctap2_err_action_timeout,
    /// User presence is required for the requested operation.
    ctap2_err_up_required,
    /// built-in user verification is disabled.
    ctap2_err_uv_blocked,
    /// A checksum did not match.
    ctap2_err_integrity_failure,
    /// The requested subcommand is either invalid or not implemented.
    ctap2_err_invalid_subcommand,
    /// built-in user verification unsuccessful. The platform SHOULD retry.
    ctap2_err_uv_invalid,
    /// The permissions parameter contains an unauthorized permission.
    ctap2_err_unauthorized_permission,
    /// Other unspecified error.
    ctap1_err_other,
    /// CTAP 2 spac last error.
    ctap2_err_spec_last,
    /// Extension specific error.
    ctap2_err_extension_first,
    ctap2_err_extension_2,
    ctap2_err_extension_3,
    ctap2_err_extension_4,
    ctap2_err_extension_5,
    ctap2_err_extension_6,
    ctap2_err_extension_7,
    ctap2_err_extension_8,
    ctap2_err_extension_9,
    ctap2_err_extension_10,
    ctap2_err_extension_11,
    ctap2_err_extension_12,
    ctap2_err_extension_13,
    ctap2_err_extension_14,
    ctap2_err_extension_15,
    /// Extension specific error.
    ctap2_err_extension_last,
    /// Vendor specific error.
    ctap2_err_vendor_first,
    ctap2_err_vendor_2,
    ctap2_err_vendor_3,
    ctap2_err_vendor_4,
    ctap2_err_vendor_5,
    ctap2_err_vendor_6,
    ctap2_err_vendor_7,
    ctap2_err_vendor_8,
    ctap2_err_vendor_9,
    ctap2_err_vendor_10,
    ctap2_err_vendor_11,
    ctap2_err_vendor_12,
    ctap2_err_vendor_13,
    ctap2_err_vendor_14,
    ctap2_err_vendor_15,
    /// Vendor specific error.
    ctap2_err_vendor_last,
    // user defined --------------
    client_timeout,
};

pub fn errorFromInt(i: u8) StatusCodes {
    return switch (i) {
        0x01 => StatusCodes.ctap1_err_invalid_command,
        0x02 => StatusCodes.ctap1_err_invalid_parameter,
        0x03 => StatusCodes.ctap1_err_invalid_length,
        0x04 => StatusCodes.ctap1_err_invalid_seq,
        0x05 => StatusCodes.ctap1_err_timeout,
        0x06 => StatusCodes.ctap1_err_channel_busy,
        0x0a => StatusCodes.ctap1_err_lock_required,
        0x0b => StatusCodes.ctap1_err_invalid_channel,
        0x11 => StatusCodes.ctap2_err_cbor_unexpected_type,
        0x12 => StatusCodes.ctap2_err_invalid_cbor,
        0x14 => StatusCodes.ctap2_err_missing_parameter,
        0x15 => StatusCodes.ctap2_err_limit_exceeded,
        0x16 => StatusCodes.ctap2_err_unsupported_extension,
        0x19 => StatusCodes.ctap2_err_credential_excluded,
        0x21 => StatusCodes.ctap2_err_processing,
        0x22 => StatusCodes.ctap2_err_invalid_credential,
        0x23 => StatusCodes.ctap2_err_user_action_pending,
        0x24 => StatusCodes.ctap2_err_operation_pending,
        0x25 => StatusCodes.ctap2_err_no_operations,
        0x26 => StatusCodes.ctap2_err_unsupported_algorithm,
        0x27 => StatusCodes.ctap2_err_operation_denied,
        0x28 => StatusCodes.ctap2_err_key_store_full,
        0x29 => StatusCodes.ctap2_err_not_busy,
        0x2a => StatusCodes.ctap2_err_no_operation_pending,
        0x2b => StatusCodes.ctap2_err_unsupported_option,
        0x2c => StatusCodes.ctap2_err_invalid_option,
        0x2d => StatusCodes.ctap2_err_keepalive_cancel,
        0x2e => StatusCodes.ctap2_err_no_credentials,
        0x2f => StatusCodes.ctap2_err_user_action_timeout,
        0x30 => StatusCodes.ctap2_err_not_allowed,
        0x31 => StatusCodes.ctap2_err_pin_invalid,
        0x32 => StatusCodes.ctap2_err_pin_blocked,
        0x33 => StatusCodes.ctap2_err_pin_auth_invalid,
        0x34 => StatusCodes.ctap2_err_pin_auth_blocked,
        0x35 => StatusCodes.ctap2_err_pin_not_set,
        0x36 => StatusCodes.ctap2_err_pin_required,
        0x37 => StatusCodes.ctap2_err_pin_policy_violation,
        0x38 => StatusCodes.ctap2_err_pin_token_expired,
        0x39 => StatusCodes.ctap2_err_request_too_large,
        0x3a => StatusCodes.ctap2_err_action_timeout,
        0x3b => StatusCodes.ctap2_err_up_required,
        0x3c => StatusCodes.ctap2_err_uv_blocked,
        0x3d => StatusCodes.ctap2_err_integrity_failure,
        0x3e => StatusCodes.ctap2_err_invalid_subcommand,
        0x3f => StatusCodes.ctap2_err_uv_invalid,
        0x40 => StatusCodes.ctap2_err_unauthorized_permission,
        0xe0 => StatusCodes.ctap2_err_extension_first,
        0xe1 => StatusCodes.ctap2_err_extension_2,
        0xe2 => StatusCodes.ctap2_err_extension_3,
        0xe3 => StatusCodes.ctap2_err_extension_4,
        0xe4 => StatusCodes.ctap2_err_extension_5,
        0xe5 => StatusCodes.ctap2_err_extension_6,
        0xe6 => StatusCodes.ctap2_err_extension_7,
        0xe7 => StatusCodes.ctap2_err_extension_8,
        0xe8 => StatusCodes.ctap2_err_extension_9,
        0xe9 => StatusCodes.ctap2_err_extension_10,
        0xea => StatusCodes.ctap2_err_extension_11,
        0xeb => StatusCodes.ctap2_err_extension_12,
        0xec => StatusCodes.ctap2_err_extension_13,
        0xed => StatusCodes.ctap2_err_extension_14,
        0xee => StatusCodes.ctap2_err_extension_15,
        0xef => StatusCodes.ctap2_err_extension_last,
        0xf0 => StatusCodes.ctap2_err_vendor_first,
        0xf1 => StatusCodes.ctap2_err_vendor_2,
        0xf2 => StatusCodes.ctap2_err_vendor_3,
        0xf3 => StatusCodes.ctap2_err_vendor_4,
        0xf4 => StatusCodes.ctap2_err_vendor_5,
        0xf5 => StatusCodes.ctap2_err_vendor_6,
        0xf6 => StatusCodes.ctap2_err_vendor_7,
        0xf7 => StatusCodes.ctap2_err_vendor_8,
        0xf8 => StatusCodes.ctap2_err_vendor_9,
        0xf9 => StatusCodes.ctap2_err_vendor_10,
        0xfa => StatusCodes.ctap2_err_vendor_11,
        0xfb => StatusCodes.ctap2_err_vendor_12,
        0xfc => StatusCodes.ctap2_err_vendor_13,
        0xfd => StatusCodes.ctap2_err_vendor_14,
        0xfe => StatusCodes.ctap2_err_vendor_15,
        0xff => StatusCodes.ctap2_err_vendor_last,
        else => StatusCodes.ctap1_err_other,
    };
}
