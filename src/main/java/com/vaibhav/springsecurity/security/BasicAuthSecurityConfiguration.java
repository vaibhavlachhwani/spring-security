package com.vaibhav.springsecurity.security;

import com.vaibhav.springsecurity.entities.UserRoles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.net.http.HttpRequest;

@Configuration
public class BasicAuthSecurityConfiguration {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity request) throws Exception {
        request
                .authorizeHttpRequests(
                        (auth) -> {
                            auth.anyRequest().authenticated();
                        }
                )
                .formLogin(form -> form.disable())
                .logout(logout -> logout.disable())
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
                );

        return request.build();
    }

    @Bean
    public UserDetailsService users() {
        UserDetails user = User.withUsername("user")
                .password("{noop}test")
                .roles(UserRoles.USER.name())
                .build();

        UserDetails admin = User.withUsername("admin")
                .password("{noop}admin!23")
                .roles(UserRoles.ADMIN.name())
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }
}
