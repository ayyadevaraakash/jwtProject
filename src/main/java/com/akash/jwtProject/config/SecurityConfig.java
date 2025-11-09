package com.akash.jwtProject.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            // disable CSRF for APIs (stateless)
            .csrf(csrf -> csrf.disable())

            // allow H2 console to render properly
            .headers(headers -> headers.frameOptions(frame -> frame.disable()))

            // enable CORS with default settings (for development)
            .cors(cors -> {})

            // set authorization rules
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/h2-console/**", "/api/auth/**").permitAll()
                    .anyRequest().authenticated()
            )

            // no sessions — use JWT instead
            .sessionManagement(session -> 
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            );

        // (JWT filter will be added here later)

        return http.build();
    }
}
