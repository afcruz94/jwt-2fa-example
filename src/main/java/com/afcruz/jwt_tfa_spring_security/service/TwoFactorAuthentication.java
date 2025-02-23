package com.afcruz.jwt_tfa_spring_security.service;

public interface TwoFactorAuthentication {
    String generateNewSecret();
    String generateQrCodeImageUri(String secret);
    boolean isOtpValid(String secret, String code);
}
