package com.soliman.JWTSecurity.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;


    // this method will return an AuthenticationResponse (token) , and it will take a
    // registerRequest (the same as user but without id)
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request){
        // we create a service class  that will have a register method
        return ResponseEntity.ok(service.register(request));
    }

    // this method will return an AuthenticationResponse (token) , and it will take an
    // AuthenticationRequest (that will have only email and password to authenticate)
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(service.authenticate(request));

    }
}
