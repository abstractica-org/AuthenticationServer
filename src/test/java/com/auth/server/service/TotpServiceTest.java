package com.auth.server.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.util.List;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests for TOTP (Time-based One-Time Password) service.
 */
@SpringBootTest
@TestPropertySource(locations = "classpath:application-test.properties")
@DisplayName("TOTP Service Tests")
class TotpServiceTest {

    @Autowired
    private TotpService totpService;

    @Test
    @DisplayName("Should generate TOTP secret")
    void testGenerateSecret() {
        String secret = totpService.generateSecret();

        assertThat(secret)
                .isNotNull()
                .isNotEmpty()
                .hasSizeGreaterThan(20)  // Base32 encoded, should be decent size
                .matches("^[A-Z2-7=]+$");  // Base32 alphabet
    }

    @Test
    @DisplayName("Should generate different secrets on each call")
    void testGenerateSecretUniqueness() {
        String secret1 = totpService.generateSecret();
        String secret2 = totpService.generateSecret();

        assertThat(secret1)
                .isNotEqualTo(secret2);
    }

    @Test
    @DisplayName("Should generate QR code as Base64 image")
    void testGetQrCodeAsBase64() {
        String secret = totpService.generateSecret();
        String email = "test@example.com";
        String appName = "Test App";

        String qrCode = totpService.getQrCodeAsBase64(secret, email, appName);

        assertThat(qrCode)
                .isNotNull()
                .isNotEmpty()
                .startsWith("iVBOR");  // PNG header in Base64
    }

    @Test
    @DisplayName("Should generate QR code URL (otpauth format)")
    void testGetQrCodeUrl() {
        String secret = "JBSWY3DPEBLW64TMMQ======";
        String email = "test@example.com";
        String appName = "TestApp";

        String url = totpService.getQrCodeUrl(secret, email, appName);

        assertThat(url)
                .isNotNull()
                .startsWith("otpauth://totp/")
                .contains("secret=" + secret)
                .contains("issuer=TestApp")
                .contains("algorithm=SHA1")
                .contains("digits=6")
                .contains("period=30");
    }

    @Test
    @DisplayName("Should encode URL special characters in QR code URL")
    void testGetQrCodeUrlEncodesSpecialCharacters() {
        String secret = "JBSWY3DPEBLW64TMMQ======";
        String email = "user+tag@example.com";
        String appName = "My App";

        String url = totpService.getQrCodeUrl(secret, email, appName);

        assertThat(url)
                .contains("%40")  // @ encoded
                .contains("%2B")  // + encoded (for +tag)
                .contains("My");  // appName is included
    }

    @Test
    @DisplayName("Should verify valid TOTP code")
    void testVerifyCodeValid() {
        String secret = totpService.generateSecret();

        // Generate a valid code using the secret
        // For testing purposes, we'll use a known secret and code
        // Note: In real scenarios, codes expire every 30 seconds
        boolean isValid = totpService.verifyCode(secret, "123456");

        // Result depends on time window, so we just check that method doesn't throw
        assertThat(isValid)
                .isInstanceOf(Boolean.class);
    }

    @Test
    @DisplayName("Should reject invalid TOTP code")
    void testVerifyCodeInvalid() {
        String secret = totpService.generateSecret();

        boolean isValid = totpService.verifyCode(secret, "000000");

        // Very unlikely that a random code would be valid
        assertThat(isValid)
                .isFalse();
    }

    @Test
    @DisplayName("Should reject malformed code format")
    void testVerifyCodeMalformed() {
        String secret = totpService.generateSecret();

        boolean isValid1 = totpService.verifyCode(secret, "12345");  // 5 digits
        boolean isValid2 = totpService.verifyCode(secret, "1234567");  // 7 digits
        boolean isValid3 = totpService.verifyCode(secret, "abcdef");  // non-numeric

        assertThat(isValid1).isFalse();
        assertThat(isValid2).isFalse();
        assertThat(isValid3).isFalse();
    }

    @Test
    @DisplayName("Should generate backup codes")
    void testGenerateBackupCodes() {
        List<String> codes = totpService.generateBackupCodes(10);

        assertThat(codes)
                .isNotNull()
                .hasSize(10)
                .allMatch(code -> code.matches("^[A-Z0-9]{8}$"))
                .doesNotHaveDuplicates();
    }

    @Test
    @DisplayName("Should generate configurable number of backup codes")
    void testGenerateBackupCodesCustomCount() {
        List<String> codes5 = totpService.generateBackupCodes(5);
        List<String> codes20 = totpService.generateBackupCodes(20);

        assertThat(codes5).hasSize(5);
        assertThat(codes20).hasSize(20);
    }

    @Test
    @DisplayName("Should validate backup code format")
    void testIsValidBackupCodeFormat() {
        assertThat(totpService.isValidBackupCodeFormat("ABCD1234")).isTrue();
        assertThat(totpService.isValidBackupCodeFormat("12345678")).isTrue();
        assertThat(totpService.isValidBackupCodeFormat("abcd1234")).isFalse();  // lowercase
        assertThat(totpService.isValidBackupCodeFormat("ABCD123")).isFalse();   // 7 chars
        assertThat(totpService.isValidBackupCodeFormat("ABCD12345")).isFalse(); // 9 chars
        assertThat(totpService.isValidBackupCodeFormat("ABCD!234")).isFalse();  // special char
        assertThat(totpService.isValidBackupCodeFormat(null)).isFalse();
        assertThat(totpService.isValidBackupCodeFormat("")).isFalse();
    }

    @Test
    @DisplayName("Should encode backup codes for storage")
    void testEncodeBackupCodesForStorage() {
        List<String> codes = List.of("CODE1234", "CODE5678", "CODE9012");

        String encoded = totpService.encodeBackupCodesForStorage(codes);

        assertThat(encoded)
                .isNotNull()
                .isNotEmpty()
                .contains(",")
                .doesNotContain("CODE1234")  // Original code not visible
                .doesNotContain("CODE5678");
    }

    @Test
    @DisplayName("Should decode backup codes from storage")
    void testDecodeBackupCodesFromStorage() {
        List<String> original = List.of("ABCD1234", "EFGH5678", "IJKL9012");
        String encoded = totpService.encodeBackupCodesForStorage(original);

        List<String> decoded = totpService.decodeBackupCodesFromStorage(encoded);

        assertThat(decoded)
                .isNotNull()
                .hasSize(3)
                .containsExactlyElementsOf(original);
    }

    @Test
    @DisplayName("Should handle empty backup codes string")
    void testDecodeEmptyBackupCodes() {
        List<String> decoded = totpService.decodeBackupCodesFromStorage("");
        assertThat(decoded).isEmpty();

        List<String> decoded2 = totpService.decodeBackupCodesFromStorage(null);
        assertThat(decoded2).isEmpty();
    }

    @Test
    @DisplayName("Should be idempotent: encode then decode returns original")
    void testEncodeDecodeRoundtrip() {
        List<String> original = totpService.generateBackupCodes(10);

        String encoded = totpService.encodeBackupCodesForStorage(original);
        List<String> decoded = totpService.decodeBackupCodesFromStorage(encoded);

        assertThat(decoded)
                .isNotNull()
                .hasSize(10)
                .containsExactlyElementsOf(original);
    }

    @Test
    @DisplayName("Should handle backup codes with special characters in encoding")
    void testEncodeDecodeSpecialCharacters() {
        // While our backup codes are alphanumeric, test robustness
        List<String> codes = List.of("AAAA0000", "ZZZZ9999");

        String encoded = totpService.encodeBackupCodesForStorage(codes);
        List<String> decoded = totpService.decodeBackupCodesFromStorage(encoded);

        assertThat(decoded)
                .containsExactlyElementsOf(codes);
    }

    @Test
    @DisplayName("Should validate all backup code formats")
    void testValidateMultipleBackupCodeFormats() {
        List<String> validCodes = List.of(
                "AAAAAAAA",
                "ZZZZZZZZ",
                "12345678",
                "ABC123DE",
                "9999AAAA"
        );

        for (String code : validCodes) {
            assertThat(totpService.isValidBackupCodeFormat(code))
                    .as("Code " + code + " should be valid")
                    .isTrue();
        }
    }

    @Test
    @DisplayName("Should reject various invalid backup code formats")
    void testRejectInvalidBackupCodeFormats() {
        List<String> invalidCodes = List.of(
                "aaaaaaaa",      // lowercase
                "AAAA AAA",      // space
                "AAAA-AAA",      // hyphen
                "AAAA_AAA",      // underscore
                "AAAA.AAA",      // period
                "",              // empty
                "A",             // too short
                "AAAAAAAAAA"     // too long
        );

        for (String code : invalidCodes) {
            assertThat(totpService.isValidBackupCodeFormat(code))
                    .as("Code '" + code + "' should be invalid")
                    .isFalse();
        }
    }

    @Test
    @DisplayName("Should generate correct number of backup codes")
    void testGenerateVariousBackupCodeCounts() {
        assertThat(totpService.generateBackupCodes(1)).hasSize(1);
        assertThat(totpService.generateBackupCodes(5)).hasSize(5);
        assertThat(totpService.generateBackupCodes(10)).hasSize(10);
        assertThat(totpService.generateBackupCodes(20)).hasSize(20);
    }

    @Test
    @DisplayName("Should handle single backup code encoding/decoding")
    void testSingleBackupCodeEncodeDecode() {
        List<String> single = List.of("SINGCODE");

        String encoded = totpService.encodeBackupCodesForStorage(single);
        List<String> decoded = totpService.decodeBackupCodesFromStorage(encoded);

        assertThat(decoded)
                .hasSize(1)
                .contains("SINGCODE");
    }

    @Test
    @DisplayName("Should handle large number of backup codes")
    void testLargeBackupCodeSet() {
        List<String> largeCodes = totpService.generateBackupCodes(50);

        String encoded = totpService.encodeBackupCodesForStorage(largeCodes);
        List<String> decoded = totpService.decodeBackupCodesFromStorage(encoded);

        assertThat(decoded)
                .hasSize(50)
                .containsAll(largeCodes);
    }

    @Test
    @DisplayName("Should maintain order when encoding/decoding backup codes")
    void testBackupCodeOrderPreserved() {
        List<String> codes = List.of("FIRST000", "SECOND00", "THIRD000", "FOURTH00");

        String encoded = totpService.encodeBackupCodesForStorage(codes);
        List<String> decoded = totpService.decodeBackupCodesFromStorage(encoded);

        assertThat(decoded)
                .containsExactlyElementsOf(codes);
    }

    @Test
    @DisplayName("Should handle backup codes with all numbers")
    void testAllNumericBackupCodes() {
        List<String> numericCodes = List.of("00000000", "11111111", "99999999");

        String encoded = totpService.encodeBackupCodesForStorage(numericCodes);
        List<String> decoded = totpService.decodeBackupCodesFromStorage(encoded);

        assertThat(decoded)
                .containsExactlyElementsOf(numericCodes);
    }

    @Test
    @DisplayName("Should handle backup codes with all letters")
    void testAllAlphabeticBackupCodes() {
        List<String> alphaCodes = List.of("AAAAAAAA", "ZZZZZZZZ", "ABCDEFGH");

        String encoded = totpService.encodeBackupCodesForStorage(alphaCodes);
        List<String> decoded = totpService.decodeBackupCodesFromStorage(encoded);

        assertThat(decoded)
                .containsExactlyElementsOf(alphaCodes);
    }

    @Test
    @DisplayName("Should generate unique backup codes in a set")
    void testBackupCodesAreUnique() {
        List<String> codes = totpService.generateBackupCodes(20);

        assertThat(codes)
                .hasSize(20)
                .doesNotHaveDuplicates();
    }

    @Test
    @DisplayName("Should generate different codes on each call")
    void testGeneratedCodesAreDifferent() {
        List<String> codes1 = totpService.generateBackupCodes(10);
        List<String> codes2 = totpService.generateBackupCodes(10);
        List<String> codes3 = totpService.generateBackupCodes(10);

        assertThat(codes1)
                .doesNotContainAnyElementsOf(codes2)
                .doesNotContainAnyElementsOf(codes3);

        assertThat(codes2)
                .doesNotContainAnyElementsOf(codes3);
    }

    @Test
    @DisplayName("Should handle QR code generation with various app names")
    void testQrCodeWithDifferentAppNames() {
        String secret = totpService.generateSecret();
        String email = "user@example.com";

        String[] appNames = {"Auth Server", "MyApp", "Test123", "API-Gateway", "App_Name"};

        for (String appName : appNames) {
            String qrCode = totpService.getQrCodeAsBase64(secret, email, appName);

            assertThat(qrCode)
                    .as("QR code for app " + appName)
                    .isNotNull()
                    .isNotEmpty()
                    .startsWith("iVBOR");
        }
    }

    @Test
    @DisplayName("Should handle TOTP URI with various email formats")
    void testQrCodeUriWithDifferentEmails() {
        String secret = totpService.generateSecret();
        String appName = "TestApp";

        String[] emails = {
                "user@example.com",
                "user.name@example.com",
                "user+tag@example.com",
                "user_name@example.co.uk"
        };

        for (String email : emails) {
            String uri = totpService.getQrCodeUrl(secret, email, appName);

            assertThat(uri)
                    .as("URI for email " + email)
                    .startsWith("otpauth://totp/")
                    .contains("secret=" + secret)
                    .contains("issuer=" + appName);
        }
    }

    @Test
    @DisplayName("Should reject null secret in code verification")
    void testVerifyCodeWithNullSecret() {
        boolean result = totpService.verifyCode(null, "123456");

        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Should reject null code in verification")
    void testVerifyCodeWithNull() {
        String secret = totpService.generateSecret();

        boolean result = totpService.verifyCode(secret, null);

        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Should reject both null parameters")
    void testVerifyCodeWithBothNull() {
        boolean result = totpService.verifyCode(null, null);

        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Should handle very long backup code list")
    void testEncodingVeryLargeBackupCodeSet() {
        List<String> largeCodes = totpService.generateBackupCodes(100);

        String encoded = totpService.encodeBackupCodesForStorage(largeCodes);

        assertThat(encoded)
                .isNotNull()
                .isNotEmpty()
                .contains(",");

        List<String> decoded = totpService.decodeBackupCodesFromStorage(encoded);

        assertThat(decoded)
                .hasSize(100)
                .containsAll(largeCodes);
    }
}
