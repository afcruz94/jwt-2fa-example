package com.afcruz.jwt_tfa_spring_security.controller.auth;

import com.afcruz.jwt_tfa_spring_security.auth.AuthenticationRequest;
import com.afcruz.jwt_tfa_spring_security.auth.AuthenticationResponse;
import com.afcruz.jwt_tfa_spring_security.auth.RegisterRequest;
import com.afcruz.jwt_tfa_spring_security.auth.VerificationRequest;
import com.afcruz.jwt_tfa_spring_security.service.AuthenticationService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationControllerV1 {
    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegisterRequest request) {
        var response = authenticationService.register(request);

        if (response != null) {
            if (request.isMfaEnabled()) return ResponseEntity.ok(response);
            else return ResponseEntity.accepted().build();
        } else {
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody AuthenticationRequest request) {
        var response = authenticationService.authenticate(request);

        if (response != null) {
            return ResponseEntity.ok(authenticationService.authenticate(request));
        } else {
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) {
        authenticationService.refreshToken(request, response);
    }

    @PostMapping("/verify-code")
    public ResponseEntity<?> verifyCode(@RequestBody VerificationRequest request) {
        return ResponseEntity.ok(authenticationService.verifyCode(request));
    }
}
