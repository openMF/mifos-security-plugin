package com.zitadel.security.service.token.controller;


import com.zitadel.security.service.token.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
public class TokenController {

    @Autowired
    TokenService tokenService;

    @PostMapping("/token")
    public ResponseEntity<?> getToken(@RequestBody Map<String, String> payload) {
        return tokenService.getToken(payload);
    }

    @PostMapping("/notifications")
    public ResponseEntity<?> getNotifications() {
        return ResponseEntity.ok("Token válido, notificación enviada");
    }


}
