package com.soliman.JWTSecurity.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JWTAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // we disable the csrf
                .csrf()
                .disable()
                // permit the authorization for the requests for these paths that matches ..
                .authorizeRequests()
                .requestMatchers("/api/v1/auth/**")
                .permitAll()
                // any other request will need to be authenticated
                .anyRequest()
                .authenticated()
                .and()
                // with JWT each request is stateless in each session
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                // we need authenticationProvider
                .and()
                .authenticationProvider(authenticationProvider) // we create this filed first using IntelliJ
                // we use the jwt filter that we created , we want to use it before the filter
                // calls UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
