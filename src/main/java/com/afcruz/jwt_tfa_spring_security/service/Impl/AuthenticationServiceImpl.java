package com.afcruz.jwt_tfa_spring_security.service.Impl;

import com.afcruz.jwt_tfa_spring_security.auth.AuthenticationRequest;
import com.afcruz.jwt_tfa_spring_security.auth.AuthenticationResponse;
import com.afcruz.jwt_tfa_spring_security.auth.RegisterRequest;
import com.afcruz.jwt_tfa_spring_security.auth.VerificationRequest;
import com.afcruz.jwt_tfa_spring_security.repository.UserRepository;
import com.afcruz.jwt_tfa_spring_security.service.AuthenticationService;
import com.afcruz.jwt_tfa_spring_security.service.TwoFactorAuthentication;
import com.afcruz.jwt_tfa_spring_security.user.Role;
import com.afcruz.jwt_tfa_spring_security.user.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.NoSuchElementException;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationServiceImpl implements AuthenticationService {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationServiceImpl.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtServiceImpl jwtService;
    private final TwoFactorAuthentication tfaAuthService;

    public AuthenticationResponse register(RegisterRequest request) {
        final String jwtToken;
        final String refreshToken;
        final String secretImageUri;
        boolean isMfaEnabled = false;

        try {
            var user = User.builder()
                    .firstname(request.getFirstname())
                    .lastname(request.getLastname())
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .role(Role.USER)
                    .isMfaEnabled(request.isMfaEnabled())
                    .build();

            if (request.isMfaEnabled()) {
                user.setSecret(tfaAuthService.generateNewSecret());
                isMfaEnabled = true;
            }

            userRepository.save(user);

            jwtToken = jwtService.generateToken(user);
            refreshToken = jwtService.generateRefreshToken(user);
            secretImageUri = tfaAuthService.generateQrCodeImageUri(user.getSecret());

        } catch (Exception e) {
            logger.error(e.getMessage());

            return null;
        }

        return AuthenticationResponse.builder()
                .secretImageUri(secretImageUri)
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .isMfaEnabled(isMfaEnabled)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        String jwtToken = "";
        String refreshToken = "";
        boolean isMfaEnabled = false;

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    request.getEmail(),
                    request.getPassword()
            ));

            var user = userRepository.findByEmail(request.getEmail()).orElseThrow();

            if (!user.isMfaEnabled()) {
                jwtToken = jwtService.generateToken(user);
                refreshToken = jwtService.generateRefreshToken(user);
            } else {
                isMfaEnabled = true;
            }

        } catch (AuthenticationException | NoSuchElementException e) {
            logger.error(e.getMessage());

            return null;
        }

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .isMfaEnabled(isMfaEnabled)
                .build();
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractUsername(refreshToken);

        if (userEmail != null) {
            try {
                var user = userRepository.findByEmail(userEmail).orElseThrow();

                if (jwtService.isTokenValid(refreshToken, user)) {
                    String accessToken = jwtService.generateToken(user);
                    var authResponse = AuthenticationResponse.builder()
                            .accessToken(accessToken)
                            .refreshToken(refreshToken)
                            .isMfaEnabled(false)
                            .build();

                    new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
                }

            } catch (AuthenticationException | NoSuchElementException | IOException e) {
                logger.error(e.getMessage());
            }
        }
    }

    public AuthenticationResponse verifyCode(VerificationRequest verificationRequest) {
        var user = userRepository.findByEmail(verificationRequest.getEmail())
                .orElseThrow(() -> new EntityNotFoundException(
                        String.format("No user found with %S", verificationRequest.getEmail()))
                );

        if (!tfaAuthService.isOtpValid(user.getSecret(), verificationRequest.getCode())) {
            logger.warn("Code is not correct");
            throw new BadCredentialsException("Code is not correct");
        }

        String jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .isMfaEnabled(user.isMfaEnabled())
                .build();
    }
}