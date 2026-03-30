package com.exmp.userservice.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;


import static java.util.Arrays.stream;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;


@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
            ) throws ServletException, IOException {

        // 1. Skip authorization for login or refresh token paths
        if(request.getServletPath().equals("/api/login") ||
            request.getServletPath().equals("/api/token/refresh")){

            filterChain.doFilter(request,response);
        }else{
            String authorizationHeader = request.getHeader(AUTHORIZATION);


            // 2. Check if the header contains a Bearer token
            if(authorizationHeader!=null && authorizationHeader.startsWith("Bearer ")){
                try{
                    String token = authorizationHeader.substring("Bearer ".length());
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();

                    // 3. Decode and verify the token
                    DecodedJWT decodedJWT = jwtVerifier.verify(token);
                    String username = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);


                    // 4. Map roles to Spring Security Authorities
                    Collection<SimpleGrantedAuthority> authorities =
                            new ArrayList<>();

                    stream(roles).forEach(role ->
                            authorities.add(new SimpleGrantedAuthority(role))
                            );

                    // 5. Authenticate the user for this specific request
                    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                            = new UsernamePasswordAuthenticationToken(username,null,authorities);
                    SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    filterChain.doFilter(request,response);
                } catch (Exception exception) {
                    // 6. Handle errors (expired token, tampered token, etc.)
                    log.error("Error logging in: {}", exception.getMessage());
                    response.setHeader("error", exception.getMessage());
                    response.setStatus(FORBIDDEN.value());

                    Map<String,String> error = new HashMap<>();
                    error.put("error_message",exception.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(),error);
                    throw new RuntimeException(exception);
                }
            }else{

                // No token? Let the request proceed (it will be blocked by SecurityConfig if the URL is protected)
                filterChain.doFilter(request,response);
            }
        }



    }
}
