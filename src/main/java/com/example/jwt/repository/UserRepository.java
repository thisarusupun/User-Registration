package com.example.jwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.jwt.entity.User;

public interface UserRepository extends JpaRepository<User,Long>{
    // additional methods
    // Custom queries
    Optional<User> findByUsername(String username);
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
}
