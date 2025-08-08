package org.apache.fineract.plugins.zitadel.security.config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SecurityConfigDebugger {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @PostConstruct
    public void init() {
        System.out.println("### Issuer URI:" + issuerUri);
    }
}
