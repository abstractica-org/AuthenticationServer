package com.auth.server.util;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.util.regex.Pattern;

/**
 * Security Validator Utility
 * <p>
 * Provides methods to detect and prevent common injection attacks:
 * - Cross-Site Scripting (XSS)
 * - SQL Injection
 * - Command Injection
 * - Path Traversal
 * - LDAP Injection
 * </p>
 */
@Slf4j
@UtilityClass
public class SecurityValidator {

    // XSS patterns - detect script tags, event handlers, and other dangerous content
    private static final Pattern XSS_PATTERN = Pattern.compile(
            "<script[^>]*>.*?</script>|" +
                    "javascript:|" +
                    "on\\w+\\s*=|" +
                    "<iframe[^>]*>|" +
                    "<object[^>]*>|" +
                    "<embed[^>]*>|" +
                    "<img[^>]*onerror|" +
                    "<svg[^>]*onload|" +
                    "<body[^>]*onload|" +
                    "<input[^>]*onfocus|" +
                    "<marquee[^>]*onstart",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );

    // SQL Injection patterns - detect common SQL keywords and dangerous characters
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            "('|(\\-\\-)|(;)|(\\|\\|)|(\\*)|" +
                    "\\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|" +
                    "SCRIPT|JAVASCRIPT|EVAL|LOAD_FILE|INTO_OUTFILE|FROM_UNIXTIME|" +
                    "BENCHMARK|SLEEP|WAITFOR)\\b|" +
                    "(/\\*.*?\\*/)|(xp_|sp_))",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );

    // Command Injection patterns - detect shell commands and dangerous characters
    private static final Pattern COMMAND_INJECTION_PATTERN = Pattern.compile(
            "[;&|`$(){}\\[\\]<>\\n\\r]|" +
                    "\\b(cat|rm|ls|chmod|chown|whoami|id|pwd|cmd|powershell|bash|sh|exec)\\b",
            Pattern.CASE_INSENSITIVE
    );

    // Path Traversal patterns - detect directory traversal attempts
    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile(
            "(\\.\\./|\\.\\\\|\\.\\.\\|%2e%2e|%2e%2e/|\\%2e\\%2e)|\\/etc\\/|c:\\\\windows|/root/",
            Pattern.CASE_INSENSITIVE
    );

    // LDAP Injection patterns
    private static final Pattern LDAP_INJECTION_PATTERN = Pattern.compile(
            "[*()&|\\\\]|" +
                    "\\b(CN|OU|DC|objectClass|uid)\\s*=",
            Pattern.CASE_INSENSITIVE
    );

    // URL encoding patterns
    private static final Pattern ENCODED_INJECTION_PATTERN = Pattern.compile(
            "%3c|%3e|%22|%27|%3b|%2d%2d|%2f|%5c|%00",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Check if input contains XSS payloads
     *
     * @param input Input string to check
     * @return true if XSS pattern detected
     */
    public static boolean containsXssPayload(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        boolean isXss = XSS_PATTERN.matcher(input).find();
        if (isXss) {
            log.warn("XSS payload detected in input");
        }
        return isXss;
    }

    /**
     * Check if input contains SQL Injection patterns
     *
     * @param input Input string to check
     * @return true if SQL injection pattern detected
     */
    public static boolean containsSqlInjection(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        boolean isSqlInjection = SQL_INJECTION_PATTERN.matcher(input).find();
        if (isSqlInjection) {
            log.warn("SQL injection pattern detected in input");
        }
        return isSqlInjection;
    }

    /**
     * Check if input contains Command Injection patterns
     *
     * @param input Input string to check
     * @return true if command injection pattern detected
     */
    public static boolean containsCommandInjection(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        boolean isCommandInjection = COMMAND_INJECTION_PATTERN.matcher(input).find();
        if (isCommandInjection) {
            log.warn("Command injection pattern detected in input");
        }
        return isCommandInjection;
    }

    /**
     * Check if input contains Path Traversal patterns
     *
     * @param input Input string to check
     * @return true if path traversal pattern detected
     */
    public static boolean containsPathTraversal(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        boolean isPathTraversal = PATH_TRAVERSAL_PATTERN.matcher(input).find();
        if (isPathTraversal) {
            log.warn("Path traversal pattern detected in input");
        }
        return isPathTraversal;
    }

    /**
     * Check if input contains LDAP Injection patterns
     *
     * @param input Input string to check
     * @return true if LDAP injection pattern detected
     */
    public static boolean containsLdapInjection(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        boolean isLdapInjection = LDAP_INJECTION_PATTERN.matcher(input).find();
        if (isLdapInjection) {
            log.warn("LDAP injection pattern detected in input");
        }
        return isLdapInjection;
    }

    /**
     * Check if input contains URL-encoded injection patterns
     *
     * @param input Input string to check
     * @return true if encoded injection pattern detected
     */
    public static boolean containsEncodedInjection(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        return ENCODED_INJECTION_PATTERN.matcher(input).find();
    }

    /**
     * Perform comprehensive security validation
     *
     * @param input Input string to validate
     * @return true if any malicious pattern detected
     */
    public static boolean isMalicious(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }

        return containsXssPayload(input) ||
                containsSqlInjection(input) ||
                containsCommandInjection(input) ||
                containsPathTraversal(input) ||
                containsLdapInjection(input) ||
                containsEncodedInjection(input);
    }

    /**
     * Sanitize input by removing dangerous patterns (permissive approach)
     * Note: This is a simple approach. For production, consider using a library like OWASP ESAPI
     *
     * @param input Input string to sanitize
     * @return Sanitized string
     */
    public static String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }

        // Remove script tags
        String sanitized = input.replaceAll("<script[^>]*>.*?</script>", "");
        // Remove event handlers
        sanitized = sanitized.replaceAll("on\\w+\\s*=\\s*['\"].*?['\"]", "");
        // Remove dangerous HTML tags
        sanitized = sanitized.replaceAll("<(iframe|object|embed|frame)[^>]*>", "");

        return sanitized;
    }

    /**
     * Check if input is valid username (alphanumeric, underscore, hyphen only)
     *
     * @param username Username to validate
     * @return true if valid
     */
    public static boolean isValidUsername(String username) {
        if (username == null || username.isEmpty()) {
            return false;
        }
        return username.matches("^[a-zA-Z0-9_-]{3,100}$");
    }

    /**
     * Check if input is valid email
     *
     * @param email Email to validate
     * @return true if valid
     */
    public static boolean isValidEmail(String email) {
        if (email == null || email.isEmpty()) {
            return false;
        }
        return email.matches("^[A-Za-z0-9+_.-]+@(.+)$");
    }

    /**
     * Check if input contains null bytes
     *
     * @param input Input to check
     * @return true if null bytes found
     */
    public static boolean containsNullBytes(String input) {
        if (input == null) {
            return false;
        }
        return input.contains("\0");
    }
}
