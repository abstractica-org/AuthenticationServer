package com.auth.server.repository;

import com.auth.server.entity.TwoFactorAuth;
import com.auth.server.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository for TwoFactorAuth entity.
 */
@Repository
public interface TwoFactorAuthRepository extends JpaRepository<TwoFactorAuth, Long> {

    /**
     * Find 2FA settings by user
     */
    Optional<TwoFactorAuth> findByUser(User user);

    /**
     * Check if user has 2FA enabled
     */
    boolean existsByUserAndEnabledIsTrue(User user);
}
