package com.example.jwtandredis2.repository;



import com.example.jwtandredis2.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    User findAllById(long id);

}