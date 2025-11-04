package com.auth.server.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * TwoFactorAuth entity for TOTP-based 2FA.
 * Stores TOTP secret and backup codes.
 */
@Entity
@Table(name = "two_factor_auth")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TwoFactorAuth {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;

    @Column(nullable = false, length = 255)
    private String secret;

    @Column(nullable = false)
    @Builder.Default
    private Boolean enabled = false;

    /**
     * Comma-separated list of backup codes (encrypted)
     */
    @Column(columnDefinition = "TEXT")
    private String backupCodes;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column
    private LocalDateTime enabledAt;

    /**
     * Verify if 2FA is active for this user
     */
    public boolean isEnabled() {
        return enabled && secret != null;
    }

    /**
     * Parse backup codes from comma-separated string
     */
    public List<String> getBackupCodesList() {
        if (backupCodes == null || backupCodes.isEmpty()) {
            return new ArrayList<>();
        }
        return List.of(backupCodes.split(","));
    }

    /**
     * Set backup codes from list
     */
    public void setBackupCodesList(List<String> codes) {
        if (codes == null || codes.isEmpty()) {
            this.backupCodes = null;
        } else {
            this.backupCodes = String.join(",", codes);
        }
    }
}
