package com.exmp.userservice.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.exmp.userservice.entity.Role;
import com.exmp.userservice.entity.User;
import com.exmp.userservice.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import com.fasterxml.jackson.databind.ObjectMapper; // Correct

import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;


@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)throws IOException{
        String authorizationHeader = httpServletRequest.getHeader(AUTHORIZATION);
        if(authorizationHeader !=null && authorizationHeader.startsWith("Bearer ")){

            try{
                String refresh_token = authorizationHeader.substring("Bearer ".length());
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(refresh_token);

                String username = decodedJWT.getSubject();
                User user = userService.getUser(username);

                String access_token = JWT.create()
                        .withSubject(user.getUserName())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                        .withIssuer(httpServletRequest.getRequestURL().toString())
                        .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                        .sign(algorithm);

                Map<String,String> token = new HashMap<>();
                token.put("access_token",access_token);
                token.put("refresh_token",refresh_token);

                httpServletResponse.setContentType(APPLICATION_JSON_VALUE);

                new ObjectMapper().writeValue(httpServletResponse.getOutputStream(),token);


            } catch (Exception exception) {
                httpServletResponse.setHeader("error", exception.getMessage());
                httpServletResponse.setStatus(FORBIDDEN.value());

                Map<String,String> error = new HashMap<>();
                error.put("error_message",exception.getMessage());
                httpServletResponse.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(httpServletResponse.getOutputStream(),error);


            }

        }else{
            throw new RuntimeException("Refresh token is missing");
        }
    }


    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers(){
        return ResponseEntity.ok().body(
            userService.getUsers()
        );

    }

    @PostMapping("/user/save")
    public ResponseEntity<User> saveUser(@RequestBody User user){
        URI uri=
        URI.create(
        ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString()
        );

        return ResponseEntity.created(uri).body(
        userService.saveUser(user)
        );
    }

}
