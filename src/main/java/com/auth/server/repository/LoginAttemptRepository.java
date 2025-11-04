package com.auth.server.repository;

import com.auth.server.entity.LoginAttempt;
import com.auth.server.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Repository for LoginAttempt entity.
 */
@Repository
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {

    /**
     * Count failed login attempts for a user within a time range
     */
    long countByUserAndSuccessIsFalseAndAttemptTimeAfter(User user, LocalDateTime afterTime);

    /**
     * Count failed login attempts for a username/email within a time range
     */
    @Query("SELECT COUNT(la) FROM LoginAttempt la WHERE la.usernameOrEmail = :usernameOrEmail AND la.success = false AND la.attemptTime > :afterTime")
    long countByUsernameOrEmailAndSuccessIsFalseAndAttemptTimeAfter(@Param("usernameOrEmail") String usernameOrEmail, @Param("afterTime") LocalDateTime afterTime);

    /**
     * Get recent login attempts for a user
     */
    List<LoginAttempt> findByUserAndAttemptTimeAfterOrderByAttemptTimeDesc(User user, LocalDateTime afterTime);

    /**
     * Get recent failed attempts for username/email
     */
    @Query("SELECT la FROM LoginAttempt la WHERE la.usernameOrEmail = :usernameOrEmail AND la.success = false AND la.attemptTime > :afterTime ORDER BY la.attemptTime DESC")
    List<LoginAttempt> findRecentFailedAttempts(@Param("usernameOrEmail") String usernameOrEmail, @Param("afterTime") LocalDateTime afterTime);

    /**
     * Count failed login attempts from a specific IP address within a time range
     */
    @Query("SELECT COUNT(la) FROM LoginAttempt la WHERE la.ipAddress = :ipAddress AND la.success = false AND la.attemptTime > :afterTime")
    long countByIpAddressAndSuccessIsFalseAndAttemptTimeAfter(@Param("ipAddress") String ipAddress, @Param("afterTime") LocalDateTime afterTime);

    /**
     * Delete old login attempts
     */
    @Query("DELETE FROM LoginAttempt la WHERE la.attemptTime < :before")
    void deleteOldAttempts(@Param("before") LocalDateTime before);
}
