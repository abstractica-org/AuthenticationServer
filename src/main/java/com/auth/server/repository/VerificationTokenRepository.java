package com.auth.server.repository;

import com.auth.server.entity.VerificationToken;
import com.auth.server.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Repository for VerificationToken entity.
 */
@Repository
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {

    /**
     * Find token by token value
     */
    Optional<VerificationToken> findByToken(String token);

    /**
     * Find token by user and token type
     */
    Optional<VerificationToken> findByUserAndTokenType(User user, VerificationToken.TokenType tokenType);

    /**
     * Delete expired tokens
     */
    @Query("DELETE FROM VerificationToken v WHERE v.expiryDate < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);

    /**
     * Count unconfirmed tokens for a user of a specific type
     */
    long countByUserAndTokenTypeAndConfirmedDateIsNull(User user, VerificationToken.TokenType tokenType);
}
