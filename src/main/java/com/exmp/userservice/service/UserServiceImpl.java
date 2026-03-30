package com.exmp.userservice.service;

import com.exmp.userservice.entity.Role;
import com.exmp.userservice.entity.User;
import com.exmp.userservice.repository.RoleRepo;
import com.exmp.userservice.repository.UserRepo;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import jakarta.annotation.Nonnull;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;


@Service
@RequiredArgsConstructor
@Transactional
@Slf4j

public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Nonnull
    public UserDetails loadUserByUsername(@Nonnull String username)throws UsernameNotFoundException{
            User user = userRepo.findByUserName(username);
            if(user==null){
               log.error("User not found in the database");
               throw new UsernameNotFoundException("User not found in the database");
            }else{
                log.info("User found in the database: {}", username);
            }
            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

        user.getRoles()
                .forEach(role ->
                        authorities.add(new SimpleGrantedAuthority(role.getName())));

            return new org.springframework.security.core.userdetails.User(
                    user.getUserName(),
                    user.getPassword(),
                    authorities
            );
    }
    @Override
    public User saveUser(User user) {
        log.info("Saving new user {} to the database", user.getName());
        user.setPassword(
        passwordEncoder.encode(
        user.getPassword()
        ));
        return userRepo.save(user);
    }

    @Override
    public void saveRole(Role role) {
        log.info("Saving new role {} to the database", role.getName());
        roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("Adding role {} to user {}", roleName, username);
        User user = userRepo.findByUserName(username);
        Role role = roleRepo.findByName(roleName);
        user.getRoles().add(role);
        // No need to call userRepo.save() because of @Transactional
    }

    @Override
    public User getUser(String username) {
        log.info("Fetching user {}", username);
        return userRepo.findByUserName(username);

    }

    @Override
    public List<User> getUsers() {
        return userRepo.findAll();
    }
}
