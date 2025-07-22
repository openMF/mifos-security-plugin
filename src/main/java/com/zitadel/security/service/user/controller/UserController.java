package com.zitadel.security.service.user.controller;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zitadel.security.api.dto.UserDetailsDTO;
import com.zitadel.security.service.apiResponse.ApiResponse;
import com.zitadel.security.service.apiResponse.ApiResponsePass;
import com.zitadel.security.service.user.dto.*;
import com.zitadel.security.service.user.roles.RoleGrantRequest;
import com.zitadel.security.service.user.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserController {

    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/crear")
    public ResponseEntity<ApiResponse<Object>> crearUsuario(@RequestBody UserDTO dto) {
            return userService.createUser(dto);
    }

    @GetMapping("/")
    public ResponseEntity<ApiResponse<ResponseZitadelDTO>> getAllUsers() {
        return userService.getUser(null);
    }

    @PutMapping("/{id}")
    public String updateUser(@PathVariable String id, @RequestBody Map<String, Object> payload) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(payload);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return "Datos recibidos";
    }

    @PostMapping("")
    public ResponseEntity<ApiResponse<ResponseZitadelDTO>> getUser(@RequestBody UserIdRequest dto) {
        System.out.println("User ID: " + dto.getUserId());
        return userService.getUser(dto.getUserId());
    }


    @PutMapping("/update-user")
    public String updateUser(@RequestBody UpdateUserRequest request) {
        return userService.updateUser(request);
    }

    @PutMapping("/update-passUser")
    public ResponseEntity<ApiResponsePass> updatePass(@RequestBody Map<String, Object> request) {
        return userService.updatePass(request);
    }

    @PostMapping("/Obtenertoken")
    public String obtenerToken() {
        return userService.obtenerToken();
    }

    @DeleteMapping("/")
    public ResponseEntity<ApiResponse<Object>> deleteUser(@RequestBody UserIdRequest request) {
        return userService.deleteUser(Long.parseLong(request.getUserId()));
    }

    @PutMapping("/desactivate")
    public ResponseEntity<ApiResponse<Object>> desactivateUser(@RequestBody UserIdRequest request) {
        return userService.desactivate(Long.valueOf(request.getUserId()));
    }

    @PutMapping("/reactivate")
    public ResponseEntity<ApiResponse<Object>> reactivateUser(@RequestBody UserIdRequest request) {
        return userService.reactivate(Long.valueOf(request.getUserId()));
    }


    @PostMapping("/assign-roles")
    public ResponseEntity<ApiResponse<Object>> assignRolesToUser(@RequestBody RoleGrantRequest data) {
        return userService.assignRolesToUser(data);
    }

    @PutMapping("/update-roles")
    public ResponseEntity<ApiResponse<Object>> updateRolesToUser(@RequestBody RoleGrantRequest data) {
        return userService.updateRolesToUser(data);
    }

    @PutMapping("/update-office")
    public ResponseEntity<ApiResponse<Object>> updateOfficeAndStaffToUser(@RequestBody OfficeUpdateRequest data) {
        return userService.updateOfficeAndStaffToUser(data);
    }


    @PostMapping("/CrearBD")
    public ResponseEntity<ApiResponse<Object>> createUserBD(@RequestBody AppUserRequest request) {
        return userService.createUserBD(request);
    }

    @PostMapping("/dataUserBD")
    public ResponseEntity<ApiResponse<Object>> getDatosExtraUsuario(@RequestBody UserIdRequest request) {
        return userService.getDatosExtraUsuario(request.getUserId());
    }

}
