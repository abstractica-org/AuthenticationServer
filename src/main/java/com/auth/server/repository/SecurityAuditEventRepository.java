package com.auth.server.repository;

import com.auth.server.entity.SecurityAuditEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Repository for security audit events
 */
@Repository
public interface SecurityAuditEventRepository extends JpaRepository<SecurityAuditEvent, UUID> {

    /**
     * Find all events for a specific user
     */
    List<SecurityAuditEvent> findByUserIdOrderByEventTimeDesc(String userId);

    /**
     * Find all events by type
     */
    List<SecurityAuditEvent> findByEventTypeOrderByEventTimeDesc(String eventType);

    /**
     * Find failed events
     */
    List<SecurityAuditEvent> findByStatusOrderByEventTimeDesc(String status);

    /**
     * Find events from a specific IP address
     */
    List<SecurityAuditEvent> findByIpAddressOrderByEventTimeDesc(String ipAddress);

    /**
     * Find events within a time range
     */
    List<SecurityAuditEvent> findByEventTimeBetweenOrderByEventTimeDesc(LocalDateTime start, LocalDateTime end);

    /**
     * Find failed events for a specific user
     */
    @Query("SELECT a FROM SecurityAuditEvent a WHERE a.userId = :userId AND a.status = 'FAILURE' ORDER BY a.eventTime DESC")
    List<SecurityAuditEvent> findFailedEventsForUser(String userId);

    /**
     * Find high-severity events
     */
    @Query("SELECT a FROM SecurityAuditEvent a WHERE a.severity IN ('HIGH', 'CRITICAL') ORDER BY a.eventTime DESC")
    List<SecurityAuditEvent> findHighSeverityEvents();

    /**
     * Find events by user and event type
     */
    List<SecurityAuditEvent> findByUserIdAndEventTypeOrderByEventTimeDesc(String userId, String eventType);

    /**
     * Paginated query for all events
     */
    Page<SecurityAuditEvent> findAllByOrderByEventTimeDesc(Pageable pageable);

    /**
     * Count failed login attempts for a user in the last N minutes
     */
    @Query("SELECT COUNT(a) FROM SecurityAuditEvent a WHERE a.username = :username AND a.eventType = 'LOGIN_FAILURE' AND a.eventTime > :since")
    long countRecentFailedLogins(String username, LocalDateTime since);

    /**
     * Count events from IP in the last N minutes
     */
    @Query("SELECT COUNT(a) FROM SecurityAuditEvent a WHERE a.ipAddress = :ipAddress AND a.eventTime > :since")
    long countRecentEventsByIp(String ipAddress, LocalDateTime since);
}
