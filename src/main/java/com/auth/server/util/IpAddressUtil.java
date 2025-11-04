package com.auth.server.util;

import jakarta.servlet.http.HttpServletRequest;
import lombok.experimental.UtilityClass;

/**
 * IP Address Utility
 * <p>
 * Extracts the client IP address from HttpServletRequest.
 * Handles proxies, load balancers, and other intermediaries.
 * </p>
 */
@UtilityClass
public class IpAddressUtil {

    /**
     * Get client IP address from request
     * <p>
     * Checks headers in order:
     * 1. X-Forwarded-For (proxy/load balancer)
     * 2. CF-Connecting-IP (Cloudflare)
     * 3. X-Client-IP (various proxies)
     * 4. X-Real-IP (nginx reverse proxy)
     * 5. Remote address (direct connection)
     * </p>
     *
     * @param request HttpServletRequest
     * @return Client IP address
     */
    public static String getClientIpAddress(HttpServletRequest request) {
        if (request == null) {
            return "unknown";
        }

        // Check X-Forwarded-For header (most common for proxies)
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isEmpty()) {
            // X-Forwarded-For can contain multiple IPs, get the first one
            return forwardedFor.split(",")[0].trim();
        }

        // Check Cloudflare header
        String cfConnectingIp = request.getHeader("CF-Connecting-IP");
        if (cfConnectingIp != null && !cfConnectingIp.isEmpty()) {
            return cfConnectingIp.trim();
        }

        // Check X-Client-IP header
        String clientIp = request.getHeader("X-Client-IP");
        if (clientIp != null && !clientIp.isEmpty()) {
            return clientIp.trim();
        }

        // Check X-Real-IP header (nginx)
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isEmpty()) {
            return realIp.trim();
        }

        // Fall back to remote address
        String remoteAddr = request.getRemoteAddr();
        return remoteAddr != null ? remoteAddr : "unknown";
    }

    /**
     * Get user agent from request
     *
     * @param request HttpServletRequest
     * @return User agent string
     */
    public static String getUserAgent(HttpServletRequest request) {
        if (request == null) {
            return "unknown";
        }
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "unknown";
    }
}
