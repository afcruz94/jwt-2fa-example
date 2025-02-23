package com.afcruz.jwt_tfa_spring_security.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;

@OpenAPIDefinition(
        info = @Info(
                contact = @Contact(
                        name = "André Cruz",
                        email = "afcruz@gmail.com",
                        url = "www.afcruz.pt"
                ),
                description = "OpenAPI documentation for 2FA Security with JWT",
                title = "OpenAPI specification - Afcruz",
                version = "1.0",
                license = @License(
                        name = "Licence name",
                        url = "https://some-licence-url.com"
                ),
                termsOfService = "Terms Of Service"
        ),
        servers = {
                @Server(
                        description = "Localhost",
                        url = "http://localhost:8080"
                )
        },
        security = {
                @SecurityRequirement(
                        name = "Bearer JWT Token"
                )
        }
)
@SecurityScheme(
        name = "Bearer Auth Token",
        description = "JWT Auth Token",
        scheme = "bearer",
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        in = SecuritySchemeIn.HEADER

)
public class OpenApiConfig {
}