package com.auth.server.config;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Security Headers Filter
 * <p>
 * Adds security-related HTTP headers to all responses to protect against
 * common web vulnerabilities including:
 * - Clickjacking (X-Frame-Options)
 * - MIME sniffing (X-Content-Type-Options)
 * - XSS attacks (X-XSS-Protection, Content-Security-Policy)
 * - Protocol downgrade (HSTS)
 * </p>
 */
@Slf4j
@Component
public class SecurityHeadersFilter implements Filter {

    @Value("${security.headers.enabled:true}")
    private boolean headersEnabled;

    @Value("${security.headers.hsts.enabled:true}")
    private boolean hstsEnabled;

    @Value("${security.headers.hsts.max-age:31536000}")
    private String hstsMaxAge;

    @Value("${security.headers.hsts.include-subdomains:true}")
    private boolean hstsIncludeSubdomains;

    @Value("${security.headers.x-frame-options:DENY}")
    private String xFrameOptions;

    @Value("${security.headers.x-content-type-options:nosniff}")
    private String xContentTypeOptions;

    @Value("${security.headers.x-xss-protection:1; mode=block}")
    private String xXssProtection;

    @Value("${security.headers.content-security-policy:default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'}")
    private String contentSecurityPolicy;

    @Value("${security.headers.referrer-policy:strict-origin-when-cross-origin}")
    private String referrerPolicy;

    @Value("${security.headers.permissions-policy:geolocation=(), microphone=(), camera=()}")
    private String permissionsPolicy;

    @Override
    public void init(FilterConfig config) throws ServletException {
        if (headersEnabled) {
            log.info("Security Headers Filter initialized. HSTS enabled: {}", hstsEnabled);
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (headersEnabled && response instanceof HttpServletResponse) {
            addSecurityHeaders((HttpServletResponse) response);
        }

        chain.doFilter(request, response);
    }

    /**
     * Add security headers to HTTP response
     */
    private void addSecurityHeaders(HttpServletResponse response) {
        // HSTS - Force HTTPS connections
        if (hstsEnabled) {
            StringBuilder hstsHeader = new StringBuilder("max-age=").append(hstsMaxAge);
            if (hstsIncludeSubdomains) {
                hstsHeader.append("; includeSubDomains");
            }
            hstsHeader.append("; preload");
            response.setHeader("Strict-Transport-Security", hstsHeader.toString());
            log.debug("Added HSTS header: {}", hstsHeader);
        }

        // X-Frame-Options - Prevent clickjacking attacks
        response.setHeader("X-Frame-Options", xFrameOptions);

        // X-Content-Type-Options - Prevent MIME sniffing
        response.setHeader("X-Content-Type-Options", xContentTypeOptions);

        // X-XSS-Protection - Legacy XSS protection for older browsers
        response.setHeader("X-XSS-Protection", xXssProtection);

        // Content-Security-Policy - Prevent XSS and other injection attacks
        response.setHeader("Content-Security-Policy", contentSecurityPolicy);

        // Referrer-Policy - Control referrer information leakage
        response.setHeader("Referrer-Policy", referrerPolicy);

        // Permissions-Policy - Control browser features and APIs
        response.setHeader("Permissions-Policy", permissionsPolicy);

        // Additional security headers
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Permitted-Cross-Domain-Policies", "none");

        log.debug("Security headers applied to response");
    }

    @Override
    public void destroy() {
        // Cleanup if needed
    }
}
