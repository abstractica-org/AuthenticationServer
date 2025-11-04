package com.auth.server.controller;

import com.auth.server.AbstractTest;
import com.auth.server.config.TestConfig;
import com.auth.server.dto.Verify2FARequest;
import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import com.auth.server.repository.RoleRepository;
import com.auth.server.repository.UserRepository;
import com.auth.server.service.TotpService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.context.annotation.Import;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests for 2FA endpoints in UserController.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties")
@Import(TestConfig.class)
@DisplayName("User Controller 2FA Tests")
class UserController2FATest extends AbstractTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private TotpService totpService;

    private User testUser;
    private String jwtToken;

    @BeforeEach
    void setUp() {
        // Clean database
        userRepository.deleteAll();
        roleRepository.deleteAll();

        // Create role
        Role userRole = Role.builder()
                .name("USER")
                .build();
        roleRepository.save(userRole);

        // Create test user
        testUser = User.builder()
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$13$hash")
                .emailVerified(true)
                .enabled(true)
                .locked(false)
                .twoFactorEnabled(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
        userRepository.save(testUser);

        // For authenticated endpoints, we would normally use a real JWT,
        // but MockMvc with @WithMockUser provides authentication context
    }

    @Test
    @DisplayName("Should initiate 2FA setup and return secret and QR code")
    @WithMockUser(username = "testuser")
    void testSetup2FA() throws Exception {
        mockMvc.perform(post("/api/users/me/2fa/setup")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.secret").exists())
                .andExpect(jsonPath("$.secret").isNotEmpty())
                .andExpect(jsonPath("$.qr_code_image").exists())
                .andExpect(jsonPath("$.qr_code_image").isNotEmpty())
                .andExpect(jsonPath("$.totp_uri").exists())
                .andExpect(jsonPath("$.totp_uri").isNotEmpty())
                .andExpect(jsonPath("$.setup_instructions").exists())
                .andExpect(jsonPath("$.message").value("2FA setup initiated. Scan the QR code with your authenticator app."));
    }

    @Test
    @DisplayName("Should reject 2FA setup verification with invalid code")
    @WithMockUser(username = "testuser")
    void testVerify2FAWithInvalidCode() throws Exception {
        // First setup 2FA
        mockMvc.perform(post("/api/users/me/2fa/setup")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        // Try to verify with invalid code
        Verify2FARequest request = Verify2FARequest.builder()
                .code("000000")
                .build();

        mockMvc.perform(post("/api/users/me/2fa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").isNotEmpty());
    }

    @Test
    @DisplayName("Should reject 2FA verification with wrong code format")
    @WithMockUser(username = "testuser")
    void testVerify2FAWithWrongFormat() throws Exception {
        mockMvc.perform(post("/api/users/me/2fa/setup")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        // Try with 5 digits
        Verify2FARequest request1 = Verify2FARequest.builder()
                .code("12345")
                .build();

        mockMvc.perform(post("/api/users/me/2fa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request1)))
                .andExpect(status().isBadRequest());

        // Try with 7 digits
        Verify2FARequest request2 = Verify2FARequest.builder()
                .code("1234567")
                .build();

        mockMvc.perform(post("/api/users/me/2fa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request2)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should reject 2FA verification with empty code")
    @WithMockUser(username = "testuser")
    void testVerify2FAWithEmptyCode() throws Exception {
        mockMvc.perform(post("/api/users/me/2fa/setup")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());

        Verify2FARequest request = Verify2FARequest.builder()
                .code("")
                .build();

        mockMvc.perform(post("/api/users/me/2fa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should reject backup code generation when 2FA not enabled")
    @WithMockUser(username = "testuser")
    void testGenerateBackupCodesWhen2FANotEnabled() throws Exception {
        mockMvc.perform(post("/api/users/me/2fa/backup-codes")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").isNotEmpty());
    }

    @Test
    @DisplayName("Should disable 2FA for user")
    @WithMockUser(username = "testuser")
    void testDisable2FA() throws Exception {
        // Enable 2FA first
        testUser.setTwoFactorEnabled(true);
        testUser.setTwoFactorSecret("JBSWY3DPEBLW64TMMQ======");
        testUser.setTwoFactorBackupCodes("encoded_codes");
        userRepository.save(testUser);

        // Verify it's enabled
        User updated = userRepository.findByUsername("testuser").orElseThrow();
        assertThat(updated.getTwoFactorEnabled()).isTrue();

        // Disable 2FA
        mockMvc.perform(delete("/api/users/me/2fa")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").isNotEmpty());

        // Verify it's disabled
        User disabled = userRepository.findByUsername("testuser").orElseThrow();
        assertThat(disabled.getTwoFactorEnabled()).isFalse();
        assertThat(disabled.getTwoFactorSecret()).isNull();
        assertThat(disabled.getTwoFactorBackupCodes()).isNull();
    }

    @Test
    @DisplayName("Should require authentication for 2FA endpoints")
    void testUnauthorizedAccess() throws Exception {
        mockMvc.perform(post("/api/users/me/2fa/setup")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/users/me/2fa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Verify2FARequest.builder().code("123456").build())))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/users/me/2fa/backup-codes")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(delete("/api/users/me/2fa")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Should get QR code in Base64 format")
    @WithMockUser(username = "testuser")
    void testQrCodeIsValidBase64() throws Exception {
        var result = mockMvc.perform(post("/api/users/me/2fa/setup")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn();

        String response = result.getResponse().getContentAsString();
        String qrCode = objectMapper.readTree(response).get("qr_code_image").asText();

        // Should start with Base64-encoded PNG header
        assertThat(qrCode)
                .startsWith("iVBOR");
    }

    @Test
    @DisplayName("Should return setup instructions")
    @WithMockUser(username = "testuser")
    void testSetupInstructionsReturned() throws Exception {
        mockMvc.perform(post("/api/users/me/2fa/setup")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.setup_instructions").exists())
                .andExpect(jsonPath("$.setup_instructions").isNotEmpty());
    }
}
