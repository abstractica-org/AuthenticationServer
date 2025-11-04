package com.auth.server.service;

import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import com.auth.server.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for CustomUserDetailsService.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("CustomUserDetailsService Tests")
public class CustomUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private CustomUserDetailsService userDetailsService;

    private User testUser;
    private Role userRole;
    private Role adminRole;

    @BeforeEach
    void setUp() {
        userRole = Role.builder()
                .id(1L)
                .name("ROLE_USER")
                .description("Standard user role")
                .build();

        adminRole = Role.builder()
                .id(2L)
                .name("ROLE_ADMIN")
                .description("Administrator role")
                .build();

        testUser = User.builder()
                .id(UUID.randomUUID())
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$13$hashedPassword123456789")
                .emailVerified(true)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
    }

    @Test
    @DisplayName("Should load user details by username")
    void testLoadUserByUsername() {
        // Given
        when(userRepository.findByUsernameOrEmail("testuser"))
                .thenReturn(Optional.of(testUser));

        // When
        UserDetails userDetails = userDetailsService.loadUserByUsername("testuser");

        // Then
        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isEqualTo("testuser");
        assertThat(userDetails.getPassword()).isEqualTo("$2a$13$hashedPassword123456789");
        assertThat(userDetails.isEnabled()).isTrue();
        assertThat(userDetails.isAccountNonLocked()).isTrue();
        assertThat(userDetails.isCredentialsNonExpired()).isTrue();
        assertThat(userDetails.isAccountNonExpired()).isTrue();
        verify(userRepository, times(1)).findByUsernameOrEmail("testuser");
    }

    @Test
    @DisplayName("Should load user details by email")
    void testLoadUserByEmail() {
        // Given
        when(userRepository.findByUsernameOrEmail("test@example.com"))
                .thenReturn(Optional.of(testUser));

        // When
        UserDetails userDetails = userDetailsService.loadUserByUsername("test@example.com");

        // Then
        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isEqualTo("testuser");
        verify(userRepository, times(1)).findByUsernameOrEmail("test@example.com");
    }

    @Test
    @DisplayName("Should load user with single role")
    void testLoadUserWithSingleRole() {
        // Given
        when(userRepository.findByUsernameOrEmail("testuser"))
                .thenReturn(Optional.of(testUser));

        // When
        UserDetails userDetails = userDetailsService.loadUserByUsername("testuser");

        // Then
        assertThat(userDetails.getAuthorities()).hasSize(1);
        assertThat(userDetails.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_USER");
    }

    @Test
    @DisplayName("Should load user with multiple roles")
    void testLoadUserWithMultipleRoles() {
        // Given
        testUser.setRoles(new HashSet<>(Set.of(userRole, adminRole)));
        when(userRepository.findByUsernameOrEmail("testuser"))
                .thenReturn(Optional.of(testUser));

        // When
        UserDetails userDetails = userDetailsService.loadUserByUsername("testuser");

        // Then
        assertThat(userDetails.getAuthorities()).hasSize(2);
        assertThat(userDetails.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    @DisplayName("Should return locked account status correctly")
    void testLoadLockedUser() {
        // Given
        testUser.setLocked(true);
        when(userRepository.findByUsernameOrEmail("testuser"))
                .thenReturn(Optional.of(testUser));

        // When
        UserDetails userDetails = userDetailsService.loadUserByUsername("testuser");

        // Then
        assertThat(userDetails.isAccountNonLocked()).isFalse();
    }

    @Test
    @DisplayName("Should return disabled account status correctly")
    void testLoadDisabledUser() {
        // Given
        testUser.setEnabled(false);
        when(userRepository.findByUsernameOrEmail("testuser"))
                .thenReturn(Optional.of(testUser));

        // When
        UserDetails userDetails = userDetailsService.loadUserByUsername("testuser");

        // Then
        assertThat(userDetails.isEnabled()).isFalse();
    }

    @Test
    @DisplayName("Should throw exception when user not found by username")
    void testLoadNonexistentUser() {
        // Given
        when(userRepository.findByUsernameOrEmail("nonexistent"))
                .thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("nonexistent"))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User not found")
                .hasMessageContaining("nonexistent");

        verify(userRepository, times(1)).findByUsernameOrEmail("nonexistent");
    }

    @Test
    @DisplayName("Should throw exception when user not found by email")
    void testLoadNonexistentUserByEmail() {
        // Given
        when(userRepository.findByUsernameOrEmail("notfound@example.com"))
                .thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("notfound@example.com"))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("User not found");
    }

    @Test
    @DisplayName("Should load user with no roles")
    void testLoadUserWithNoRoles() {
        // Given
        testUser.setRoles(new HashSet<>());
        when(userRepository.findByUsernameOrEmail("testuser"))
                .thenReturn(Optional.of(testUser));

        // When
        UserDetails userDetails = userDetailsService.loadUserByUsername("testuser");

        // Then
        assertThat(userDetails.getAuthorities()).isEmpty();
    }

    @Test
    @DisplayName("Should correctly map all account flags")
    void testLoadUserAllAccountFlags() {
        // Given
        testUser.setEnabled(true);
        testUser.setLocked(false);
        when(userRepository.findByUsernameOrEmail("testuser"))
                .thenReturn(Optional.of(testUser));

        // When
        UserDetails userDetails = userDetailsService.loadUserByUsername("testuser");

        // Then
        assertThat(userDetails.isAccountNonExpired()).isTrue();
        assertThat(userDetails.isCredentialsNonExpired()).isTrue();
        assertThat(userDetails.isAccountNonLocked()).isTrue();
        assertThat(userDetails.isEnabled()).isTrue();
    }
}
