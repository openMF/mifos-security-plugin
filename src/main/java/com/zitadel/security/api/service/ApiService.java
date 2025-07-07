package com.zitadel.security.api.service;


import com.zitadel.security.api.dto.UserDetailsDTO;
import com.zitadel.security.service.apiResponse.ApiResponse;
import org.springframework.http.ResponseEntity;

import java.util.Map;

public interface ApiService {
    ResponseEntity<ApiResponse<UserDetailsDTO>> userDetails(Map<String, String> tokenMap);
    ResponseEntity<ApiResponse<UserDetailsDTO>> mapToken(Map<String, Object> tokenPayload);
    ResponseEntity<?> getToken(Map<String, String> payload);
    ResponseEntity<String> getProjectRoles();


}
