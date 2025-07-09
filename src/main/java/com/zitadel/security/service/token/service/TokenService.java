package com.zitadel.security.service.token.service;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.Map;

public interface TokenService {
    ResponseEntity<?> getToken(Map<String, String> payload);
}
