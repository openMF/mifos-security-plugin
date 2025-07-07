package com.zitadel.security;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;

public class ZitadelTokenValidator {

    private final JwtDecoder jwtDecoder;

    public ZitadelTokenValidator(String issuerUri) {
        this.jwtDecoder = JwtDecoders.fromIssuerLocation(issuerUri);
    }

    public Jwt validate(String token) {
        try {
            return jwtDecoder.decode(token);
        } catch (JwtException e) {
            throw new RuntimeException("Invalid JWT Token: " + e.getMessage(), e);
        }
    }
}
