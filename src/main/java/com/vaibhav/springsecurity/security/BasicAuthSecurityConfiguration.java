package com.vaibhav.springsecurity.security;

import com.vaibhav.springsecurity.entities.UserRoles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
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
                )
                .headers(
                        (header) -> {
                            header
                                    .frameOptions(
                                            (frame) -> {
                                                frame.sameOrigin();
                                            }
                                    );
                        }
                );

        return request.build();
    }

//    @Bean
//    public UserDetailsService users() {
//        UserDetails user = User.withUsername("user")
//                .password("{noop}test")
//                .roles(UserRoles.USER.name())
//                .build();
//
//        UserDetails admin = User.withUsername("admin")
//                .password("{noop}admin!23")
//                .roles(UserRoles.ADMIN.name())
//                .build();
//
//        return new InMemoryUserDetailsManager(user, admin);
//    }

    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    @Bean
    public UserDetailsService users(DataSource dataSource) {
        UserDetails user = User.withUsername("user")
//                .password("{noop}test")
                .password("test")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles(UserRoles.USER.name())
                .build();

        UserDetails admin = User.withUsername("admin")
//                .password("{noop}admin!23")
                .password("admin")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles(UserRoles.ADMIN.name())
                .build();

        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
