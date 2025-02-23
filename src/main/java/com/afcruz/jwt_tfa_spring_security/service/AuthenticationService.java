package com.afcruz.jwt_tfa_spring_security.service;

import com.afcruz.jwt_tfa_spring_security.auth.AuthenticationRequest;
import com.afcruz.jwt_tfa_spring_security.auth.AuthenticationResponse;
import com.afcruz.jwt_tfa_spring_security.auth.RegisterRequest;
import com.afcruz.jwt_tfa_spring_security.auth.VerificationRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthenticationService {
    AuthenticationResponse register(RegisterRequest request);
    AuthenticationResponse authenticate(AuthenticationRequest request);
    void refreshToken(HttpServletRequest request, HttpServletResponse response);
    AuthenticationResponse verifyCode(VerificationRequest verificationRequest);
}
