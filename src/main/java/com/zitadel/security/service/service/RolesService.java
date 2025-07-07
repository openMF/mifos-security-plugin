package com.zitadel.security.service.service;


import com.zitadel.security.service.apiResponse.ApiResponse;
import com.zitadel.security.service.dto.RoleRequest;
import org.springframework.http.ResponseEntity;

public interface RolesService {
    ResponseEntity<ApiResponse<Object>> getRoles();
    ResponseEntity<ApiResponse<Object>> createRol(RoleRequest data);
    ResponseEntity<ApiResponse<Object>> deleteRol(String roleKey);
    ResponseEntity<ApiResponse<Object>> updateRol(String roleKey, RoleRequest data);
}
