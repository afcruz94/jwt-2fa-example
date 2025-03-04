package com.afcruz.jwt_tfa_spring_security.service.Impl;

import com.afcruz.jwt_tfa_spring_security.service.TwoFactorAuthentication;
import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class TwoFactorAuthenticationServiceImpl implements TwoFactorAuthentication {
    @Value("${spring.application.qrcode-label}")
    private String qrCodeLabel;
    @Value("${spring.application.qrcode-issuer}")
    private String qrCodeIssuer;

    public String generateNewSecret() {
        return new DefaultSecretGenerator().generate();
    }

    public String generateQrCodeImageUri(String secret) {
        QrData data = new QrData.Builder()
                .label(qrCodeLabel)
                .secret(secret)
                .issuer(qrCodeIssuer)
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

        QrGenerator generator = new ZxingPngQrGenerator();
        byte[] imageDate = new byte[0];

        try {
            imageDate = generator.generate(data);
        } catch (QrGenerationException e) {
            log.error(e.getMessage());
        }

        return Utils.getDataUriForImage(imageDate, generator.getImageMimeType());
    }

    public boolean isOtpValid(String secret, String code) {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        CodeVerifier codeVerifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

        return codeVerifier.isValidCode(secret, code);
    }
}
