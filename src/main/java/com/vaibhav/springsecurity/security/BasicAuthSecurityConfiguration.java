package com.vaibhav.springsecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import java.net.http.HttpRequest;

@Configuration
public class BasicAuthSecurityConfiguration {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity request) throws Exception {
        return request
                .authorizeHttpRequests(
                        (auth) -> {
                            auth.anyRequest().authenticated();
                        }
                )
                .formLogin(form -> form.disable())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(
                        (session) -> {
                            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                        }
                )
                .csrf(
                        (csrf) -> {
                            csrf.disable();
                        }
                )
                .build();
    }
}
