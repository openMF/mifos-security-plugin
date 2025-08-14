package org.apache.fineract.infrastructure.zitadel.security.config;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SecurityConfigDebugger {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityConfigDebugger.class);

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @PostConstruct
    public void init() {
        logger.debug("### Issuer URI:" + issuerUri);
    }
}
