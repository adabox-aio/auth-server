package io.adabox.auth.repositories;

import io.adabox.auth.repositories.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

    @Query("select u from User u where u.email=?1")
    User findByEmail(String email);

    @Query("select u from User u where u.stakeKey=?1")
    Optional<User> findByStakeKey(String stakeKey);

    Optional<User> findByUsername(String username);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    @Transactional
    @Modifying
    @Query("UPDATE User u set u.isEmailVerified=true where u.email=?1")
    void activateEmail(String email);
}