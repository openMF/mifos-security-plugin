package org.apache.fineract.plugins.zitadel.security.service;

import org.apache.fineract.plugins.zitadel.security.api.dto.*;
import org.apache.fineract.plugins.zitadel.security.api.response.ApiResponse;
import org.apache.fineract.plugins.zitadel.security.api.response.ApiResponsePass;
import org.springframework.http.ResponseEntity;

import java.util.Map;

public interface ApiService {
    ResponseEntity<ApiResponse<Object>> getRoles();
    ResponseEntity<ApiResponse<Object>> createRol(RoleRequest data);
    ResponseEntity<ApiResponse<Object>> deleteRol(String roleKey);
    ResponseEntity<ApiResponse<Object>> updateRol(String roleKey, RoleRequest data);
    ResponseEntity<?> getToken(Map<String, String> payload);
    ResponseEntity<ApiResponse<Object>> createUser(UserDTO userDTO);
    ResponseEntity<ApiResponse<ResponseZitadelDTO>> getUser(String id);
    String obtenerToken();
    String updateUser(UpdateUserRequest request);
    ResponseEntity<ApiResponsePass> updatePass(Map<String, Object> jsonBody);
    ResponseEntity<ApiResponse<Object>> deleteUser(Long userId);
    ResponseEntity<ApiResponse<Object>> desactivate(Long userId);
    ResponseEntity<ApiResponse<Object>> reactivate(Long userId);
    ResponseEntity<ApiResponse<Object>> getUserById(Long userId);
    ResponseEntity<ApiResponse<Object>> assignRolesToUser(RoleGrantRequest data);
    ResponseEntity<ApiResponse<Object>> updateRolesToUser(RoleGrantRequest data);
    ResponseEntity<ApiResponse<Object>> createUserBD(AppUserRequest request);
    ResponseEntity<ApiResponse<Object>> updateOfficeAndStaffToUser(OfficeUpdateRequest data);
    ResponseEntity<ApiResponse<Object>> getDatosExtraUsuario(String userId);
    ResponseEntity<ApiResponse<UserDetailsDTO>> mapToken(Map<String, Object> tokenPayload);
    ResponseEntity<ApiResponse<UserDetailsDTO>> userDetails(Map<String, String> tokenMap);
    ResponseEntity<String> getProjectRoles();
}
