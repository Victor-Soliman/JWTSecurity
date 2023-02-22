package com.soliman.JWTSecurity.auth;

import com.soliman.JWTSecurity.config.JwtService;
import com.soliman.JWTSecurity.user.Role;
import com.soliman.JWTSecurity.user.User;
import com.soliman.JWTSecurity.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    // this method will allow us to create a user and save it in the DB , and return the generated token out of it
    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        repository.save(user);

        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // to do authentication you use AuthenticationManagerBean : we inject it in the top
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        // till here the user is authenticated , it remains to generate the token and send it
        // try to find the user by email first
        User user = repository.findByEmail(request.getEmail()).orElseThrow();

        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();

    }
}
