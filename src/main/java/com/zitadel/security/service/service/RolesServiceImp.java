package com.zitadel.security.service.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zitadel.security.service.apiResponse.ApiResponse;
import com.zitadel.security.service.dto.RoleRequest;
import com.zitadel.security.service.user.service.UserService;
import com.zitadel.security.service.user.service.UserServiceImp;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class RolesServiceImp implements RolesService {

    @Autowired
    private UserService userService;

    @Value("${zitadel.proyect_id}")
    private String proyectId;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.uri}")
    private String uri;



    @Override
    public ResponseEntity<ApiResponse<Object>> getRoles() {
        try {

            String url = uri+"/management/v1/projects/" + proyectId + "/roles/_search";
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(userService.obtenerToken());
            headers.setContentType(MediaType.APPLICATION_JSON);

            JSONObject json = new JSONObject();
            HttpEntity<String> entity = new HttpEntity<>(json.toString(), headers);

            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.POST, entity, Object.class);

            return ResponseEntity.ok(new ApiResponse<>(200, "GET Roles", response.getBody()));

        } catch (HttpClientErrorException e) {
            return handleZitadelError(e);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Error inesperado: " + e.getMessage(), null));
        }

    }

    private UserServiceImp userServiceImp;

    @Override
    public ResponseEntity<ApiResponse<Object>> createRol(RoleRequest data) {
        try {
            String url = uri+"/management/v1/projects/" + proyectId + "/roles";
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(userService.obtenerToken());
            headers.setContentType(MediaType.APPLICATION_JSON);

            JSONObject json = new JSONObject();
            json.put("roleKey", data.getRoleKey());
            json.put("displayName", data.getDisplayName());
            json.put("group", data.getGroup() != null ? data.getGroup() : "");

            HttpEntity<String> entity = new HttpEntity<>(json.toString(), headers);

            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.POST, entity, Object.class);

            return ResponseEntity.ok(new ApiResponse<>(200, "Rol creado correctamente", response.getBody()));

        } catch (HttpClientErrorException e) {
            return handleZitadelError(e);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Error inesperado: " + e.getMessage(), null));
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> deleteRol(String roleKey) {
        try {
            String url = uri+"/management/v1/projects/" + proyectId + "/roles/" + roleKey;

            RestTemplate restTemplate = new RestTemplate();

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(userService.obtenerToken());
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<String> entity = new HttpEntity<>(headers);

            ResponseEntity<Object> response = restTemplate.exchange(
                    url,
                    HttpMethod.DELETE,
                    entity,
                    Object.class
            );

            return ResponseEntity.ok(
                    new ApiResponse<>(200, "Rol eliminado correctamente", response.getBody())
            );

        } catch (HttpClientErrorException e) {
            return handleZitadelError(e);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Error inesperado: " + e.getMessage(), null));
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> updateRol(String roleKey, RoleRequest data) {
        try {
            String url = uri+"/management/v1/projects/" + proyectId + "/roles/" + roleKey;

            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(userService.obtenerToken());
            headers.setContentType(MediaType.APPLICATION_JSON);

            JSONObject payload = new JSONObject();
            payload.put("displayName", data.getDisplayName());
            payload.put("group", data.getGroup() != null ? data.getGroup() : "");

            HttpEntity<String> entity = new HttpEntity<>(payload.toString(), headers);

            ResponseEntity<Object> response = restTemplate.exchange(
                    url,
                    HttpMethod.PUT,
                    entity,
                    Object.class
            );

            return ResponseEntity.ok(new ApiResponse<>(200, "Rol actualizado correctamente", response.getBody()));

        } catch (HttpClientErrorException e) {
            return handleZitadelError(e);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Error inesperado: " + e.getMessage(), null));
        }
    }

    // TODO: Bad_Request, maneja el error del consumo y se queda interno dependiendo del codigo recivido ya sea 5 o 9, si fuera diferente es directo un BAD_REQUEST
    private ResponseEntity<ApiResponse<Object>> handleZitadelError(HttpClientErrorException e) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> errorJson = mapper.readValue(e.getResponseBodyAsString(), Map.class);

            int code = (int) errorJson.getOrDefault("code", 400);
            String message = (String) errorJson.getOrDefault("message", "Error desconocido");
            Object details = errorJson.get("details");

            HttpStatus status = (code == 5) ? HttpStatus.NOT_FOUND : (code == 9) ? HttpStatus.ACCEPTED : HttpStatus.BAD_REQUEST;

            return ResponseEntity.status(status)
                    .body(new ApiResponse<>(code, message, details));

        } catch (Exception parseException) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>(400, "Error al parsear el mensaje de error", null));
        }
    }
}
