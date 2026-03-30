package com.exmp.userservice.service;

import com.exmp.userservice.entity.Role;
import com.exmp.userservice.entity.User;

import java.util.List;

public interface UserService {
    // Persists a new user to the database [cite: 59]
    User saveUser(User user);

    // Persists a new role to the database [cite: 60]
    void saveRole(Role role);

    // Links a specific role to a user by their unique names [cite: 61]
    void addRoleToUser(String username, String roleName);

    // Retrieves a single user by their username [cite: 62]
    User getUser(String username);

    // Retrieves a list of all users in the system [cite: 63]
    List<User> getUsers();
}
