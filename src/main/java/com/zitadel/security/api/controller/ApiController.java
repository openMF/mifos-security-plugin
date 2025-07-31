package com.zitadel.security.api.controller;


import com.zitadel.security.api.dto.UserDetailsDTO;
import com.zitadel.security.api.service.ApiService;
import com.zitadel.security.service.apiResponse.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestWrapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import jakarta.servlet.http.HttpServletResponse;
import java.util.*;

@RestController
class ApiController {

    private ArrayList<String> tasks = new ArrayList<>();
    private static final Logger log = LoggerFactory.getLogger(ApiController.class);

    @Autowired
    ApiService apiService;

    @PostMapping("/userdetails")
    public ResponseEntity<ApiResponse<UserDetailsDTO>> userDetails(@RequestBody Map<String, String> tokenMap) {
        return apiService.userDetails(tokenMap);
    }

    @PostMapping("/DTO-token")
    public ResponseEntity<ApiResponse<UserDetailsDTO>> mapToken(@RequestBody Map<String, Object> tokenPayload) {
        return apiService.mapToken(tokenPayload);
    }

    @GetMapping("/api/project-roles")
    public ResponseEntity<String> getProjectRoles() {
        return apiService.getProjectRoles();
    }

    @PostMapping("/tokenOIDC")
    public ResponseEntity<?> getToken(@RequestBody Map<String, String> payload) {
        return apiService.getToken(payload);
    }

    @GetMapping("/api/healthz")
    Object healthz() {
        return "OK";
    }

    @GetMapping(value = "/api/tasks", produces = MediaType.APPLICATION_JSON_VALUE)
    Object tasks(SecurityContextHolderAwareRequestWrapper requestWrapper) {
        if (this.tasks.size() > 0 || !requestWrapper.isUserInRole("ROLE_admin")) {
            return this.tasks;
        }
        log.debug("Entrando a la llamada");
        return Arrays.asList("add the first task");
    }

    @PostMapping(value = "/api/tasks", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    Object addTask(@RequestBody String task, HttpServletResponse response) {
        if (task.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "task must not be empty");
        }
        this.tasks.add(task);
        return "task added";
    }


}