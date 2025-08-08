package org.apache.fineract.plugins.zitadel.security.controller;

import org.apache.fineract.plugins.zitadel.security.api.dto.*;
import org.apache.fineract.plugins.zitadel.security.service.ApiService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.apache.fineract.plugins.zitadel.security.api.response.ApiResponse;
import org.apache.fineract.plugins.zitadel.security.api.response.ApiResponsePass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class Controlador {

    private ArrayList<String> tasks = new ArrayList<>();
    private static final Logger log = LoggerFactory.getLogger(Controlador.class);

    @Autowired
    ApiService apiService;

    @Autowired
    ApiService userService;

    @Autowired
    ApiService rolesService;


    // Sin seguridad
    @GetMapping("/test")
    public ResponseEntity<String> test() {
        return ResponseEntity.ok("test from plugin");
    }

    // Con seguridad
    @GetMapping("/test2")
    public ResponseEntity<String> test2() {
        return ResponseEntity.ok("test from plugin with security filter");
    }

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

    @GetMapping("/roles")
    public ResponseEntity<ApiResponse<Object>> listRoles() {
        return rolesService.getRoles();
    }

    @PostMapping("/roles")
    public ResponseEntity<ApiResponse<Object>> createRol(@RequestBody RoleRequest data) {
        return rolesService.createRol(data);
    }

    @DeleteMapping("/roles")
    public ResponseEntity<ApiResponse<Object>> deleteRol( @RequestBody RoleRequest data) {
        String id= data.getRoleKey();
        return rolesService.deleteRol(id);
    }

    @PutMapping("/roles")
    public ResponseEntity<ApiResponse<Object>> updateRol( @RequestBody RoleRequest data) {
        String id= data.getRoleKey();
        return rolesService.updateRol(id, data);
    }

    @PostMapping("/user/crear")
    public ResponseEntity<ApiResponse<Object>> crearUsuario(@RequestBody UserDTO dto) {
        return userService.createUser(dto);
    }

    @GetMapping("/user/")
    public ResponseEntity<ApiResponse<ResponseZitadelDTO>> getAllUsers() {
        return userService.getUser(null);
    }

    @PutMapping("/user/{id}")
    public String updateUser(@PathVariable String id, @RequestBody Map<String, Object> payload) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(payload);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return "Datos recibidos";
    }

    @PostMapping("/user")
    public ResponseEntity<ApiResponse<ResponseZitadelDTO>> getUser(@RequestBody UserIdRequest dto) {
        System.out.println("User ID: " + dto.getUserId());
        return userService.getUser(dto.getUserId());
    }

    @PutMapping("/user/update-user")
    public String updateUser(@RequestBody UpdateUserRequest request) {
        return userService.updateUser(request);
    }

    @PutMapping("/user/update-passUser")
    public ResponseEntity<ApiResponsePass> updatePass(@RequestBody Map<String, Object> request) {
        return userService.updatePass(request);
    }

    @PostMapping("/user/Obtenertoken")
    public String obtenerToken() {
        return userService.obtenerToken();
    }

    @DeleteMapping("/user/")
    public ResponseEntity<ApiResponse<Object>> deleteUser(@RequestBody UserIdRequest request) {
        return userService.deleteUser(Long.parseLong(request.getUserId()));
    }

    @PutMapping("/user/desactivate")
    public ResponseEntity<ApiResponse<Object>> desactivateUser(@RequestBody UserIdRequest request) {
        return userService.desactivate(Long.valueOf(request.getUserId()));
    }

    @PutMapping("/user/reactivate")
    public ResponseEntity<ApiResponse<Object>> reactivateUser(@RequestBody UserIdRequest request) {
        return userService.reactivate(Long.valueOf(request.getUserId()));
    }

    @PostMapping("/user/assign-roles")
    public ResponseEntity<ApiResponse<Object>> assignRolesToUser(@RequestBody RoleGrantRequest data) {
        return userService.assignRolesToUser(data);
    }

    @PutMapping("/user/update-roles")
    public ResponseEntity<ApiResponse<Object>> updateRolesToUser(@RequestBody RoleGrantRequest data) {
        return userService.updateRolesToUser(data);
    }

    @PutMapping("/user/update-office")
    public ResponseEntity<ApiResponse<Object>> updateOfficeAndStaffToUser(@RequestBody OfficeUpdateRequest data) {
        return userService.updateOfficeAndStaffToUser(data);
    }

    @PostMapping("/user/CrearBD")
    public ResponseEntity<ApiResponse<Object>> createUserBD(@RequestBody AppUserRequest request) {
        return userService.createUserBD(request);
    }

    @PostMapping("/user/dataUserBD")
    public ResponseEntity<ApiResponse<Object>> getDatosExtraUsuario(@RequestBody UserIdRequest request) {
        return userService.getDatosExtraUsuario(request.getUserId());
    }

    @PostMapping("/notifications")
    public ResponseEntity<?> getNotifications() {
        return ResponseEntity.ok("Token válido, notificación enviada");
    }


}
