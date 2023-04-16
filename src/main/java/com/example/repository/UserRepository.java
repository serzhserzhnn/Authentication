package com.example.repository;

import com.example.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

    List<User> findByUsernameContainingIgnoreCase(String name);

    @Modifying
    @Transactional
    @Query("Update User t SET t.password=:pass WHERE t.id=:id")
    void updatePass(@Param("id") Long id, @Param("pass") String pass);
}
