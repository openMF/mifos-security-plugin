package com.zitadel.security.service.controller;

import com.zitadel.security.service.apiResponse.ApiResponse;
import com.zitadel.security.service.dto.RoleRequest;
import com.zitadel.security.service.service.RolesService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/roles")
public class RolesController {

    @Autowired
    private RolesService rolesService;

    @GetMapping("")

    public ResponseEntity<ApiResponse<Object>> listRoles() {
        return rolesService.getRoles();
    }

    @PostMapping("")

    public ResponseEntity<ApiResponse<Object>> createRol(@RequestBody RoleRequest data) {
        return rolesService.createRol(data);
    }

    @DeleteMapping("/{roleKey}")
    public ResponseEntity<ApiResponse<Object>> deleteRol(@PathVariable String roleKey) {
        return rolesService.deleteRol(roleKey);
    }

    @PutMapping("/{roleKey}")
    public ResponseEntity<ApiResponse<Object>> updateRol(@PathVariable String roleKey, @RequestBody RoleRequest data) {
        return rolesService.updateRol(roleKey, data);
    }

}
