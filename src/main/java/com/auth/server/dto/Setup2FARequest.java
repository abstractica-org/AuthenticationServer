package com.auth.server.dto;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request to initiate 2FA setup.
 * User sends this to receive secret and QR code.
 * No fields needed - just a trigger endpoint.
 */
@Data
@NoArgsConstructor
@Builder
public class Setup2FARequest {
}
