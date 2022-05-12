package io.adabox.auth.repositories;

import io.adabox.auth.repositories.models.ERole;
import io.adabox.auth.repositories.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(ERole name);
}