package org.apache.fineract.infrastructure.zitadel.security.controller;

import org.apache.fineract.infrastructure.zitadel.security.service.ApiService;
import org.springframework.http.ResponseEntity;
import org.apache.fineract.infrastructure.zitadel.security.api.response.ApiResponse;
import org.apache.fineract.infrastructure.zitadel.security.api.response.ApiResponsePass;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import org.apache.fineract.infrastructure.zitadel.security.api.dto.AppUserRequest;
import org.apache.fineract.infrastructure.zitadel.security.api.dto.OfficeUpdateRequest;
import org.apache.fineract.infrastructure.zitadel.security.api.dto.ResponseZitadelDTO;
import org.apache.fineract.infrastructure.zitadel.security.api.dto.RoleGrantRequest;
import org.apache.fineract.infrastructure.zitadel.security.api.dto.RoleRequest;
import org.apache.fineract.infrastructure.zitadel.security.api.dto.UpdateUserRequest;
import org.apache.fineract.infrastructure.zitadel.security.api.dto.UserDTO;
import org.apache.fineract.infrastructure.zitadel.security.api.dto.UserDetailsDTO;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@RestController
@RequestMapping("/authentication")
public class SecurityController {

    @Autowired
    ApiService apiService;

    @PostMapping("/token")
    public ResponseEntity<?> token(@RequestBody Map<String, String> payload) {
        return apiService.getToken(payload);
    }

    @PostMapping("/userdetails")
    public ResponseEntity<ApiResponse<UserDetailsDTO>> userDetails(@RequestBody Map<String, String> tokenMap) {
        return apiService.userDetails(tokenMap);
    }

    @GetMapping("/role")
    public ResponseEntity<ApiResponse<Object>> listRoles() {
        return apiService.getRoles();
    }

    @PostMapping("/role")
    public ResponseEntity<ApiResponse<Object>> createRol(@RequestBody RoleRequest data) {
        return apiService.createRol(data);
    }

    @PutMapping("/role")
    public ResponseEntity<ApiResponse<Object>> updateRol( @RequestBody RoleRequest data) {
        return apiService.updateRol(data.getRoleKey(), data);
    }

    @DeleteMapping("/role/{id}")
    public ResponseEntity<ApiResponse<Object>> deleteRol( @PathVariable String id) {
        return apiService.deleteRol(id);
    }

    @GetMapping("/user")
    public ResponseEntity<ApiResponse<ResponseZitadelDTO>> allUsers() {
        return apiService.getUser(null);
    }

    @PostMapping("/user")
    public ResponseEntity<ApiResponse<Object>> createUser(@RequestBody UserDTO dto) {
        return apiService.createUser(dto);
    }

    @PutMapping("/user")
    public String updateUser(@RequestBody UpdateUserRequest request) {
        return apiService.updateUser(request);
    }

    @DeleteMapping("/user/{id}")
    public ResponseEntity<ApiResponse<Object>> deleteUser(@PathVariable String id) {
        return apiService.deleteUser(Long.parseLong(id));
    }

    @GetMapping("/user/{id}")
    public ResponseEntity<ApiResponse<ResponseZitadelDTO>> userById(@PathVariable String id) {
        return apiService.getUser(id);
    }

    @PutMapping("/user/password")
    public ResponseEntity<ApiResponsePass> updatePass(@RequestBody Map<String, Object> request) {
        return apiService.updatePass(request);
    }

    @PostMapping("/user/db")
    public ResponseEntity<ApiResponse<Object>> createUserBD(@RequestBody AppUserRequest request) {
        return apiService.createUserBD(request);
    }

    @GetMapping("/user/db/{id}")
    public ResponseEntity<ApiResponse<Object>> userByIdDb(@PathVariable String id) {
        return apiService.getdataExtraUser(id);
    }

    @PutMapping("/user/des/{id}")
    public ResponseEntity<ApiResponse<Object>> desactivateUser(@PathVariable String id) {
        return apiService.desactivate(Long.valueOf(id));
    }

    @PutMapping("/user/act/{id}")
    public ResponseEntity<ApiResponse<Object>> reactivateUser(@PathVariable String id) {
        return apiService.reactivate(Long.valueOf(id));
    }

    @PostMapping("/user/role")
    public ResponseEntity<ApiResponse<Object>> assignRolesToUser(@RequestBody RoleGrantRequest data) {
        return apiService.assignRolesToUser(data);
    }

    @PutMapping("/user/role")
    public ResponseEntity<ApiResponse<Object>> updateRolesToUser(@RequestBody RoleGrantRequest data) {
        return apiService.updateRolesToUser(data);
    }

    @PutMapping("/user/office")
    public ResponseEntity<ApiResponse<Object>> updateOfficeAndStaffToUser(@RequestBody OfficeUpdateRequest data) {
        return apiService.updateOfficeAndStaffToUser(data);
    }
}
