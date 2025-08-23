package org.apache.fineract.infrastructure.zitadel.security.service;

import org.apache.fineract.infrastructure.zitadel.security.api.dto.*;
import org.apache.fineract.infrastructure.zitadel.security.api.response.ApiResponse;
import org.apache.fineract.infrastructure.zitadel.security.api.response.ApiResponsePass;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

public interface ApiService {
    ResponseEntity<?> handleSession(Map<String, String> headers, String payload);
    ResponseEntity<?> getToken(Map<String, String> payload);
    ResponseEntity<ApiResponse<UserDetailsDTO>> mapToken(Map<String, Object> tokenPayload);
    ResponseEntity<ApiResponse<UserDetailsDTO>> userDetails(Map<String, String> tokenMap);
    ResponseEntity<String> getProjectRoles();
    ResponseEntity<ApiResponse<Object>> getRoles();
    ResponseEntity<ApiResponse<Object>> createRol(RoleRequest data);
    ResponseEntity<ApiResponse<Object>> deleteRol(String roleKey);
    ResponseEntity<ApiResponse<Object>> updateRol(String roleKey, RoleRequest data);
    ResponseEntity<ApiResponse<ResponseZitadelDTO>> getUser(String id);
    ResponseEntity<ApiResponse<Object>> createUser(UserDTO userDTO);
    String updateUser(UpdateUserRequest request);
    ResponseEntity<ApiResponse<Object>> deleteUser(Long userId);
    ResponseEntity<ApiResponsePass> updatePass(Map<String, Object> jsonBody);
    ResponseEntity<ApiResponse<Object>> createUserBD(AppUserRequest request);
    ResponseEntity<ApiResponse<Object>> getdataExtraUser(String userId);
    ResponseEntity<ApiResponse<Object>> desactivate(Long userId);
    ResponseEntity<ApiResponse<Object>> reactivate(Long userId);
    ResponseEntity<ApiResponse<Object>> assignRolesToUser(RoleGrantRequest data);
    ResponseEntity<ApiResponse<Object>> updateRolesToUser(RoleGrantRequest data);
    ResponseEntity<ApiResponse<Object>> updateOfficeAndStaffToUser(OfficeUpdateRequest data);
    String getToken();
    ResponseEntity<ApiResponse<Object>> getUserById(Long userId);
    String afterStartup();
    String afterStartupUser(List<UserZitadelDto> allUsers);
}
