package com.afcruz.jwt_tfa_spring_security.auditing;

import com.afcruz.jwt_tfa_spring_security.user.User;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class ApplicationAuditAware implements AuditorAware<String> {
    @Override
    public Optional<String> getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken)
            return Optional.empty();

        User userPrincipal = (User) authentication.getPrincipal();

        return Optional.of(userPrincipal.getFirstname() + "_" + userPrincipal.getLastname());
    }
}
