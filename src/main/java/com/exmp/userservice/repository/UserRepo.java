package com.exmp.userservice.repository;

import com.exmp.userservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepo extends JpaRepository<User,Long> {
    User findByUserName(String username);
}
