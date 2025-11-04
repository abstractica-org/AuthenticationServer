package com.auth.server.service;

import com.auth.server.dto.RegisterRequest;
import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import com.auth.server.exception.ResourceNotFoundException;
import com.auth.server.exception.UserAlreadyExistsException;
import com.auth.server.repository.RoleRepository;
import com.auth.server.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for UserService.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserService Tests")
public class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuditService auditService;

    @InjectMocks
    private UserService userService;

    private RegisterRequest registerRequest;
    private Role userRole;
    private User testUser;

    @BeforeEach
    void setUp() {
        registerRequest = RegisterRequest.builder()
                .username("newuser")
                .email("newuser@example.com")
                .password("Test@1234")
                .passwordConfirm("Test@1234")
                .build();

        userRole = Role.builder()
                .id(1L)
                .name("ROLE_USER")
                .description("Standard user role")
                .build();

        testUser = User.builder()
                .id(UUID.randomUUID())
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$13$hashedPassword")
                .emailVerified(true)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
    }

    @Test
    @DisplayName("Should register user successfully")
    void testRegisterUserSuccess() {
        // Given
        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("newuser@example.com")).thenReturn(false);
        when(passwordEncoder.encode("Test@1234")).thenReturn("encodedPassword");
        when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(userRole));
        when(userRepository.save(any(User.class))).thenReturn(testUser);

        // When
        User registeredUser = userService.registerUser(registerRequest);

        // Then
        assertThat(registeredUser).isNotNull();
        assertThat(registeredUser.getUsername()).isEqualTo("testuser");
        verify(userRepository, times(1)).existsByUsername("newuser");
        verify(userRepository, times(1)).existsByEmail("newuser@example.com");
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    @DisplayName("Should throw exception when username already exists")
    void testRegisterUserWithDuplicateUsername() {
        // Given
        when(userRepository.existsByUsername("newuser")).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> userService.registerUser(registerRequest))
                .isInstanceOf(UserAlreadyExistsException.class)
                .hasMessageContaining("Username already exists");

        verify(userRepository, times(1)).existsByUsername("newuser");
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should throw exception when email already exists")
    void testRegisterUserWithDuplicateEmail() {
        // Given
        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.existsByEmail("newuser@example.com")).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> userService.registerUser(registerRequest))
                .isInstanceOf(UserAlreadyExistsException.class)
                .hasMessageContaining("Email already exists");

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should find user by ID")
    void testFindUserById() {
        // Given
        when(userRepository.findById(testUser.getId())).thenReturn(Optional.of(testUser));

        // When
        User foundUser = userService.findById(testUser.getId());

        // Then
        assertThat(foundUser).isEqualTo(testUser);
        verify(userRepository, times(1)).findById(testUser.getId());
    }

    @Test
    @DisplayName("Should throw exception when user not found by ID")
    void testFindUserByIdNotFound() {
        // Given
        UUID nonexistentId = UUID.randomUUID();
        when(userRepository.findById(nonexistentId)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> userService.findById(nonexistentId))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("User not found");
    }

    @Test
    @DisplayName("Should find user by username")
    void testFindUserByUsername() {
        // Given
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // When
        User foundUser = userService.findByUsername("testuser");

        // Then
        assertThat(foundUser).isEqualTo(testUser);
        verify(userRepository, times(1)).findByUsername("testuser");
    }

    @Test
    @DisplayName("Should find user by email")
    void testFindUserByEmail() {
        // Given
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));

        // When
        User foundUser = userService.findByEmail("test@example.com");

        // Then
        assertThat(foundUser).isEqualTo(testUser);
        verify(userRepository, times(1)).findByEmail("test@example.com");
    }

    @Test
    @DisplayName("Should verify user password")
    void testVerifyPassword() {
        // Given
        when(passwordEncoder.matches("Test@1234", "$2a$13$hashedPassword")).thenReturn(true);

        // When
        boolean isValid = userService.verifyPassword(testUser, "Test@1234");

        // Then
        assertThat(isValid).isTrue();
        verify(passwordEncoder, times(1)).matches("Test@1234", "$2a$13$hashedPassword");
    }

    @Test
    @DisplayName("Should reject invalid password")
    void testVerifyInvalidPassword() {
        // Given
        when(passwordEncoder.matches("WrongPassword", "$2a$13$hashedPassword")).thenReturn(false);

        // When
        boolean isValid = userService.verifyPassword(testUser, "WrongPassword");

        // Then
        assertThat(isValid).isFalse();
    }

    @Test
    @DisplayName("Should update user password")
    void testUpdatePassword() {
        // Given
        when(passwordEncoder.encode("NewPassword@123")).thenReturn("newEncodedPassword");
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        userService.updatePassword(testUser, "NewPassword@123");

        // Then
        assertThat(testUser.getPasswordHash()).isEqualTo("newEncodedPassword");
        verify(userRepository, times(1)).save(testUser);
        verify(passwordEncoder, times(1)).encode("NewPassword@123");
    }

    @Test
    @DisplayName("Should verify email")
    void testVerifyEmail() {
        // Given
        testUser.setEmailVerified(false);
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        userService.verifyEmail(testUser);

        // Then
        assertThat(testUser.getEmailVerified()).isTrue();
        verify(userRepository, times(1)).save(testUser);
    }

    @Test
    @DisplayName("Should lock user account")
    void testLockUser() {
        // Given
        assertThat(testUser.getLocked()).isFalse();
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        userService.lockUser(testUser);

        // Then
        assertThat(testUser.getLocked()).isTrue();
        verify(userRepository, times(1)).save(testUser);
    }

    @Test
    @DisplayName("Should unlock user account")
    void testUnlockUser() {
        // Given
        testUser.setLocked(true);
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        userService.unlockUser(testUser);

        // Then
        assertThat(testUser.getLocked()).isFalse();
        verify(userRepository, times(1)).save(testUser);
    }

    @Test
    @DisplayName("Should disable user")
    void testDisableUser() {
        // Given
        assertThat(testUser.getEnabled()).isTrue();
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        userService.disableUser(testUser);

        // Then
        assertThat(testUser.getEnabled()).isFalse();
        verify(userRepository, times(1)).save(testUser);
    }

    @Test
    @DisplayName("Should enable user")
    void testEnableUser() {
        // Given
        testUser.setEnabled(false);
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        userService.enableUser(testUser);

        // Then
        assertThat(testUser.getEnabled()).isTrue();
        verify(userRepository, times(1)).save(testUser);
    }

    @Test
    @DisplayName("Should check if user exists by username")
    void testExistsByUsername() {
        // Given
        when(userRepository.existsByUsername("testuser")).thenReturn(true);
        when(userRepository.existsByUsername("nonexistent")).thenReturn(false);

        // When
        boolean exists = userService.existsByUsername("testuser");
        boolean notExists = userService.existsByUsername("nonexistent");

        // Then
        assertThat(exists).isTrue();
        assertThat(notExists).isFalse();
    }

    @Test
    @DisplayName("Should check if user exists by email")
    void testExistsByEmail() {
        // Given
        when(userRepository.existsByEmail("test@example.com")).thenReturn(true);
        when(userRepository.existsByEmail("nonexistent@example.com")).thenReturn(false);

        // When
        boolean exists = userService.existsByEmail("test@example.com");
        boolean notExists = userService.existsByEmail("nonexistent@example.com");

        // Then
        assertThat(exists).isTrue();
        assertThat(notExists).isFalse();
    }

    @Test
    @DisplayName("Should check account is active")
    void testIsAccountActive() {
        // Given
        testUser.setEnabled(true);
        testUser.setLocked(false);

        // When
        boolean isActive = testUser.isAccountActive();

        // Then
        assertThat(isActive).isTrue();
    }

    @Test
    @DisplayName("Should return false when account is locked")
    void testIsAccountActiveWhenLocked() {
        // Given
        testUser.setEnabled(true);
        testUser.setLocked(true);

        // When
        boolean isActive = testUser.isAccountActive();

        // Then
        assertThat(isActive).isFalse();
    }

    @Test
    @DisplayName("Should return false when account is disabled")
    void testIsAccountActiveWhenDisabled() {
        // Given
        testUser.setEnabled(false);
        testUser.setLocked(false);

        // When
        boolean isActive = testUser.isAccountActive();

        // Then
        assertThat(isActive).isFalse();
    }
}
