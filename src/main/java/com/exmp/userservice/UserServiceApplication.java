package com.exmp.userservice;

import com.exmp.userservice.entity.Role;
import com.exmp.userservice.entity.User;
import com.exmp.userservice.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class UserServiceApplication {

    public static void main(String[] args) {

        SpringApplication.run(UserServiceApplication.class, args);
    }

    @Bean
    CommandLineRunner run(UserService userService){
        return args->{

            //seeding roles

            userService.saveRole(
                    new Role(null,"ROLE_MANAGER")
            );
            userService.saveRole(
                    new Role(null,"ROLE_ADMIN")
            );
            userService.saveRole(
                    new Role(null, "ROLE_USER")
            );

            userService.saveRole(
                    new Role(null, "ROLE_SUPER_ADMIN")
            );


            //seeding user
            userService.saveUser(
                    new User(null, "John Traore", "john", "1234", new ArrayList<>())
            );
            userService.saveUser(
                    new User(null, "Will Smith", "will", "1234", new ArrayList<>())
            );
            userService.saveUser(
                    new User(null, "Jim Carry", "jim", "1234", new ArrayList<>())
            );
            userService.saveUser(
                    new User(null, "Arnold Schwarzenegger", "arnold", "1234", new ArrayList<>())
            );



            // Assigning Roles to Users
            userService.addRoleToUser("john", "ROLE_USER");
            userService.addRoleToUser("will", "ROLE_MANAGER");
            userService.addRoleToUser("jim", "ROLE_ADMIN");
            userService.addRoleToUser("arnold", "ROLE_SUPER_ADMIN");
            userService.addRoleToUser("arnold", "ROLE_ADMIN");
            userService.addRoleToUser("arnold", "ROLE_USER");

        };

    }
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
