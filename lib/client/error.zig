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
    ctap1_err_tiemout,
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
    /// Extension specific error.
    ctap2_err_extension_last,
    /// Vendor specific error.
    ctap2_err_vendor_first,
    /// Vendor specific error.
    ctap2_err_vendor_last,
};

pub fn errorFromInt(i: u8) StatusCodes {
    return switch (i) {
        0x01 => StatusCodes.ctap1_err_invalid_command,
        0x02 => StatusCodes.ctap1_err_invalid_parameter,
        0x03 => StatusCodes.ctap1_err_invalid_length,
        else => StatusCodes.ctap1_err_other,
    };
}
