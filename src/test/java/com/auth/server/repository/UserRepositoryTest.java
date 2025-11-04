package com.auth.server.repository;

import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for UserRepository.
 */
@DataJpaTest
@ActiveProfiles("test")
@DisplayName("UserRepository Tests")
public class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    private User testUser;
    private Role userRole;

    @BeforeEach
    void setUp() {
        // Create default role
        userRole = roleRepository.save(Role.builder()
                .name("ROLE_USER")
                .description("Standard user role")
                .build());

        // Create test user
        testUser = User.builder()
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$13$hashedPasswordHash123456789")
                .emailVerified(true)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();

        userRepository.save(testUser);
    }

    @Test
    @DisplayName("Should save and retrieve user by ID")
    void testSaveAndFindById() {
        // When
        Optional<User> foundUser = userRepository.findById(testUser.getId());

        // Then
        assertThat(foundUser)
                .isPresent()
                .contains(testUser);
    }

    @Test
    @DisplayName("Should find user by username")
    void testFindByUsername() {
        // When
        Optional<User> foundUser = userRepository.findByUsername("testuser");

        // Then
        assertThat(foundUser)
                .isPresent()
                .hasValueSatisfying(user -> {
                    assertThat(user.getUsername()).isEqualTo("testuser");
                    assertThat(user.getEmail()).isEqualTo("test@example.com");
                });
    }

    @Test
    @DisplayName("Should return empty when username not found")
    void testFindByUsernameNotFound() {
        // When
        Optional<User> foundUser = userRepository.findByUsername("nonexistent");

        // Then
        assertThat(foundUser).isEmpty();
    }

    @Test
    @DisplayName("Should find user by email")
    void testFindByEmail() {
        // When
        Optional<User> foundUser = userRepository.findByEmail("test@example.com");

        // Then
        assertThat(foundUser)
                .isPresent()
                .hasValueSatisfying(user -> {
                    assertThat(user.getUsername()).isEqualTo("testuser");
                    assertThat(user.getEmail()).isEqualTo("test@example.com");
                });
    }

    @Test
    @DisplayName("Should return empty when email not found")
    void testFindByEmailNotFound() {
        // When
        Optional<User> foundUser = userRepository.findByEmail("nonexistent@example.com");

        // Then
        assertThat(foundUser).isEmpty();
    }

    @Test
    @DisplayName("Should find user by username or email")
    void testFindByUsernameOrEmail() {
        // When - find by username
        Optional<User> foundByUsername = userRepository.findByUsernameOrEmail("testuser");
        // When - find by email
        Optional<User> foundByEmail = userRepository.findByUsernameOrEmail("test@example.com");

        // Then
        assertThat(foundByUsername).isPresent();
        assertThat(foundByEmail).isPresent();
        assertThat(foundByUsername.get().getId()).isEqualTo(foundByEmail.get().getId());
    }

    @Test
    @DisplayName("Should check username exists")
    void testExistsByUsername() {
        // When
        boolean exists = userRepository.existsByUsername("testuser");
        boolean notExists = userRepository.existsByUsername("nonexistent");

        // Then
        assertThat(exists).isTrue();
        assertThat(notExists).isFalse();
    }

    @Test
    @DisplayName("Should check email exists")
    void testExistsByEmail() {
        // When
        boolean exists = userRepository.existsByEmail("test@example.com");
        boolean notExists = userRepository.existsByEmail("nonexistent@example.com");

        // Then
        assertThat(exists).isTrue();
        assertThat(notExists).isFalse();
    }

    @Test
    @DisplayName("Should update user")
    void testUpdateUser() {
        // When
        testUser.setEmail("newemail@example.com");
        testUser.setEmailVerified(false);
        userRepository.save(testUser);

        // Then
        Optional<User> updatedUser = userRepository.findById(testUser.getId());
        assertThat(updatedUser)
                .isPresent()
                .hasValueSatisfying(user -> {
                    assertThat(user.getEmail()).isEqualTo("newemail@example.com");
                    assertThat(user.getEmailVerified()).isFalse();
                });
    }

    @Test
    @DisplayName("Should lock user")
    void testLockUser() {
        // When
        testUser.setLocked(true);
        userRepository.save(testUser);

        // Then
        Optional<User> lockedUser = userRepository.findById(testUser.getId());
        assertThat(lockedUser)
                .isPresent()
                .hasValueSatisfying(user -> assertThat(user.getLocked()).isTrue());
    }

    @Test
    @DisplayName("Should disable user")
    void testDisableUser() {
        // When
        testUser.setEnabled(false);
        userRepository.save(testUser);

        // Then
        Optional<User> disabledUser = userRepository.findById(testUser.getId());
        assertThat(disabledUser)
                .isPresent()
                .hasValueSatisfying(user -> assertThat(user.getEnabled()).isFalse());
    }

    @Test
    @DisplayName("Should delete user")
    void testDeleteUser() {
        // When
        userRepository.delete(testUser);

        // Then
        Optional<User> deletedUser = userRepository.findById(testUser.getId());
        assertThat(deletedUser).isEmpty();
    }

    @Test
    @DisplayName("Should return user with roles")
    void testUserWithRoles() {
        // When
        Optional<User> foundUser = userRepository.findById(testUser.getId());

        // Then
        assertThat(foundUser)
                .isPresent()
                .hasValueSatisfying(user -> {
                    assertThat(user.getRoles()).isNotEmpty();
                    assertThat(user.getRoles()).contains(userRole);
                });
    }

    @Test
    @DisplayName("Should find user case-insensitive by username")
    void testFindByUsernameIgnoreCase() {
        // When
        Optional<User> foundUser = userRepository.findByUsernameIgnoreCase("TESTUSER");

        // Then
        assertThat(foundUser)
                .isPresent()
                .hasValueSatisfying(user -> assertThat(user.getUsername()).isEqualTo("testuser"));
    }

    @Test
    @DisplayName("Should find user case-insensitive by email")
    void testFindByEmailIgnoreCase() {
        // When
        Optional<User> foundUser = userRepository.findByEmailIgnoreCase("TEST@EXAMPLE.COM");

        // Then
        assertThat(foundUser)
                .isPresent()
                .hasValueSatisfying(user -> assertThat(user.getEmail()).isEqualTo("test@example.com"));
    }
}
