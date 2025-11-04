package com.auth.server.repository;

import com.auth.server.entity.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for RoleRepository.
 */
@DataJpaTest
@ActiveProfiles("test")
@DisplayName("RoleRepository Tests")
public class RoleRepositoryTest {

    @Autowired
    private RoleRepository roleRepository;

    private Role testRole;

    @BeforeEach
    void setUp() {
        testRole = roleRepository.save(Role.builder()
                .name("ROLE_ADMIN")
                .description("Administrator role")
                .build());
    }

    @Test
    @DisplayName("Should save and retrieve role by ID")
    void testSaveAndFindById() {
        // When
        Optional<Role> foundRole = roleRepository.findById(testRole.getId());

        // Then
        assertThat(foundRole)
                .isPresent()
                .contains(testRole);
    }

    @Test
    @DisplayName("Should find role by name")
    void testFindByName() {
        // When
        Optional<Role> foundRole = roleRepository.findByName("ROLE_ADMIN");

        // Then
        assertThat(foundRole)
                .isPresent()
                .hasValueSatisfying(role -> {
                    assertThat(role.getName()).isEqualTo("ROLE_ADMIN");
                    assertThat(role.getDescription()).isEqualTo("Administrator role");
                });
    }

    @Test
    @DisplayName("Should return empty when role name not found")
    void testFindByNameNotFound() {
        // When
        Optional<Role> foundRole = roleRepository.findByName("ROLE_NONEXISTENT");

        // Then
        assertThat(foundRole).isEmpty();
    }

    @Test
    @DisplayName("Should check if role exists by name")
    void testExistsByName() {
        // When
        boolean exists = roleRepository.existsByName("ROLE_ADMIN");
        boolean notExists = roleRepository.existsByName("ROLE_NONEXISTENT");

        // Then
        assertThat(exists).isTrue();
        assertThat(notExists).isFalse();
    }

    @Test
    @DisplayName("Should update role")
    void testUpdateRole() {
        // When
        testRole.setDescription("Updated description");
        roleRepository.save(testRole);

        // Then
        Optional<Role> updatedRole = roleRepository.findById(testRole.getId());
        assertThat(updatedRole)
                .isPresent()
                .hasValueSatisfying(role -> assertThat(role.getDescription()).isEqualTo("Updated description"));
    }

    @Test
    @DisplayName("Should delete role")
    void testDeleteRole() {
        // When
        roleRepository.delete(testRole);

        // Then
        Optional<Role> deletedRole = roleRepository.findById(testRole.getId());
        assertThat(deletedRole).isEmpty();
    }
}
