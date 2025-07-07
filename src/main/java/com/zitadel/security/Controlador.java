package com.zitadel.security;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class Controlador {

    @GetMapping("test")
    public ResponseEntity<Object> test() {
        return ResponseEntity.ok().body("test");
    }

    @GetMapping("test2")
    public ResponseEntity<Object> test2() {
        return ResponseEntity.ok().body("test2");
    }
}
