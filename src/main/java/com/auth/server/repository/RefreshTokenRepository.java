package com.auth.server.repository;

import com.auth.server.entity.RefreshToken;
import com.auth.server.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository for RefreshToken entity.
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    /**
     * Find refresh token by token value
     */
    Optional<RefreshToken> findByTokenValue(String tokenValue);

    /**
     * Find all valid (non-revoked, non-replaced) refresh tokens for a user
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user = :user AND rt.revoked = false AND rt.replacedByToken IS NULL AND rt.expiryDate > CURRENT_TIMESTAMP")
    List<RefreshToken> findValidTokensByUser(@Param("user") User user);

    /**
     * Delete expired tokens
     */
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);

    /**
     * Delete old revoked tokens
     */
    @Query("DELETE FROM RefreshToken rt WHERE rt.revoked = true AND rt.createdAt < :before")
    void deleteOldRevokedTokens(@Param("before") LocalDateTime before);

    /**
     * Count valid tokens for a user
     */
    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.user = :user AND rt.revoked = false AND rt.replacedByToken IS NULL AND rt.expiryDate > CURRENT_TIMESTAMP")
    long countValidTokensByUser(@Param("user") User user);
}
