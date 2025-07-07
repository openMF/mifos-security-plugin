package com.zitadel.security.service.user.service;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.zitadel.security.service.apiResponse.ApiResponse;
import com.zitadel.security.service.apiResponse.ApiResponsePass;
import com.zitadel.security.service.user.dto.*;
import com.zitadel.security.service.user.repository.AppUserService;
import com.zitadel.security.service.user.roles.RoleGrantRequest;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.json.JSONArray;
import org.json.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
public class UserServiceImp implements UserService {

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.uri}")
    private String uri;

    private final RestTemplate restTemplate = new RestTemplate();

    @Autowired
    AppUserService appUserService;

    @Value("${zitadel.proyect_id}")
    private String proyectId;

    @Value("${zitadel.urltoken}")
    private String tokenUrl;


    @Value("${zitadel.urluser}")
    private String urlUser;


    @Value("${zitadel.scope}")
    private String scopetoken;


    @Value("${zitadel.client_id}")
    private String clientId;

    @Value("${zitadel.client_secret}")
    private String client_secret;

    @Value("${zitadel.proyect_grand_id}")
    private String projectGrantId;


    @Override
    public String obtenerToken() {
        try {

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "client_credentials");
            body.add("client_id", clientId);
            body.add("client_secret", client_secret);
            body.add("scope", scopetoken);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            RestTemplate restTemplate = new RestTemplate();

            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                Map<String, Object> responseBody = response.getBody();
                if (responseBody != null && responseBody.containsKey("access_token")) {
                    return responseBody.get("access_token").toString();
                } else {
                    throw new RuntimeException("Token no encontrado en la respuesta");
                }
            } else {
                throw new RuntimeException("Error al obtener el token: " + response.getStatusCode());
            }
        } catch (HttpClientErrorException e) {
            throw new RuntimeException("Error al obtener el token de Zitadel", e);
        } catch (Exception e) {
            throw new RuntimeException("Error inesperado al obtener el token", e);
        }
    }


    @Override
    public ResponseEntity<ApiResponse<Object>> createUser(UserDTO dto) {
        try {

            OkHttpClient client = new OkHttpClient();

            Map<String, Object> profile = Map.of(
                    "firstName", dto.getGivenName(),
                    "lastName", dto.getFamilyName(),
                    "displayName", dto.getDisplayName(),
                    "nickName", dto.getNickName(),
                    "preferredLanguage", dto.getPreferredLanguage(),
                    "gender", dto.getGender()
            );

            Map<String, Object> email = Map.of(
                    "email", dto.getEmail(),
                    "isEmailVerified", false
            );

            Map<String, Object> phone = Map.of(
                    "phone", dto.getPhone(),
                    "isPhoneVerified", true
            );

            Map<String, Object> password = Map.of(
                    "password", dto.getPassword(),
                    "changeRequired", true
            );

            Map<String, Object> initialLogin = Map.of(
                    "returnToUrl", "https://example.com/email/verify"
            );

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("userName", dto.getUsername());
            payload.put("organizationId", dto.getOrganizationId());
            payload.put("profile", profile);
            payload.put("email", email);
            payload.put("phone", phone);
            payload.put("password", password);
            payload.put("initialLogin", initialLogin);

            ObjectMapper mapper = new ObjectMapper();
            String json = mapper.writeValueAsString(payload);

            RequestBody body = RequestBody.create(json, okhttp3.MediaType.parse("application/json"));

            Request request = new Request.Builder()
                    .url(urlUser)
                    .post(body)
                    .addHeader("Authorization", "Bearer " + obtenerToken())
                    .addHeader("Content-Type", "application/json")
                    .build();

            Response response = client.newCall(request).execute();

            if (!response.isSuccessful()) {
                String responseBody = response.body() != null ? response.body().string() : "Sin cuerpo";
                throw new RuntimeException("Error al crear usuario en Zitadel: " + responseBody);
            }

            String responseBody = response.body().string();
            Map<String, Object> responseData = mapper.readValue(responseBody, Map.class);

            return ResponseEntity.ok(new ApiResponse<>(200, "Usuario creado correctamente", responseData));

        } catch (Exception e) {
            throw new RuntimeException("Error al crear usuario en Zitadel", e);
        }
    }


    @Override
    public ResponseEntity<ApiResponse<ResponseZitadelDTO>> getUser(String id) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(obtenerToken());
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<ResponseZitadelDTO> response = restTemplate.exchange(
                    uri+"/management/v1/users/_search",
                    HttpMethod.POST,
                    entity,
                    ResponseZitadelDTO.class
            );

            ResponseZitadelDTO responseBody = response.getBody();

            if (responseBody != null && responseBody.getResult() != null) {
                List<UserZitadelDto> allUsers = responseBody.getResult();

                if (id == null || id.isEmpty()) {
                    return ResponseEntity.ok(new ApiResponse<>(200, "Usuarios obtenidos", responseBody));
                }

                List<UserZitadelDto> filteredUsers = allUsers.stream()
                        .filter(user -> id.equals(user.getId()))
                        .collect(Collectors.toList());

                ResponseZitadelDTO filteredResponse = new ResponseZitadelDTO();
                filteredResponse.setDetails(responseBody.getDetails());
                filteredResponse.setResult(filteredUsers);

                return ResponseEntity.ok(new ApiResponse<>(200, "Usuarios obtenidos", filteredResponse));
            }

            return ResponseEntity.ok(new ApiResponse<>(404, "Usuario no encontrado", null));
        } catch (Exception e) {
            return ResponseEntity.ok(new ApiResponse<>(400, "Error al obtener el usuario", null));
        }
    }



    @Override
    public String updateUser(UpdateUserRequest req) {
        String baseUrl = uri + "/v2/users/";
        StringBuilder result = new StringBuilder();

        if (req.email != null) {
            result.append(postRequest(baseUrl + req.userId + "/email", obtenerToken(), req.email));
        }

        if (req.phone != null) {
            result.append(postRequest(baseUrl + req.userId + "/phone", obtenerToken(), req.phone));
        }

        if (req.profile != null) {
            String url = baseUrl + "human/" + req.userId;

            String body = """
            {
              "userId": "%s",
              "username": "%s",
              "profile": {
                "givenName": "%s",
                "familyName": "%s",
                "displayName": "%s",
                "nickName": "%s",
                "preferredLanguage": "%s",
                "gender": "%s"
              }
            }
            """.formatted(
                    req.userId,
                    req.profile.username,
                    req.profile.givenName,
                    req.profile.familyName,
                    req.profile.displayName,
                    req.profile.nickName,
                    req.profile.preferredLanguage,
                    req.profile.gender
            );
            result.append(putRequest(url, obtenerToken(), body));
            appUserService.actualizarDatosUsuario(req.userId, req.profile.username, req.profile.givenName, req.profile.familyName);


        }

        return result.toString();
    }

    @Override
    public ResponseEntity<ApiResponsePass> updatePass(Map<String, Object> jsonBody) {
        String baseUrl = uri + "/v2/users/";
        String userId = (String) jsonBody.get("userId");
        String token = obtenerToken();

        if (userId == null || token == null) {
            ApiResponsePass error = new ApiResponsePass(400, "Faltan campos requeridos: 'userId' o 'token'");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }

        jsonBody.remove("userId");
        jsonBody.remove("token");

        String url = baseUrl + userId + "/password";
        return sendRequest2(url, token, jsonBody, HttpMethod.POST);
    }


    private String postRequest(String url, String token, Object body) {
        return sendRequest(url, token, body, HttpMethod.POST);
    }

    private String putRequest(String url, String token, Object body) {
        return sendRequest(url, token, body, HttpMethod.PUT);
    }

    private ResponseEntity<ApiResponsePass> sendRequest2(String url, String token, Object body, HttpMethod method) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(token);

            HttpEntity<Object> entity = new HttpEntity<>(body, headers);

            ResponseEntity<String> response = restTemplate.exchange(url, method, entity, String.class);

            ApiResponsePass success = new ApiResponsePass(response.getStatusCodeValue(), "Operación exitosa");
            return ResponseEntity.status(response.getStatusCode()).body(success);

        } catch (HttpStatusCodeException e) {
            ApiResponsePass error = new ApiResponsePass(e.getRawStatusCode(), e.getResponseBodyAsString());
            return ResponseEntity.status(e.getStatusCode()).body(error);
        } catch (Exception e) {
            e.printStackTrace();
            ApiResponsePass error = new ApiResponsePass(500, "Error interno del servidor: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    private String sendRequest(String url, String token, Object body, HttpMethod method) {

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(token);
            HttpEntity<Object> entity = new HttpEntity<>(body, headers);

            ResponseEntity<String> response = restTemplate.exchange(url, method, entity, String.class);

            return "\n[" + method + "] " + url + ": " + response.getStatusCode();
        } catch (Exception e) {
            return "\n[" + method + "] " + url + ": ERROR - " + e.getMessage();
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> deleteUser(Long userId) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(obtenerToken());
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<ResponseZitadelDTO> response = restTemplate.exchange(
                    uri+"/v2/users/" + userId,
                    HttpMethod.DELETE,
                    entity,
                    ResponseZitadelDTO.class
            );
            appUserService.eliminarUsuarioConRoles(userId.toString());
            return ResponseEntity.ok(new ApiResponse<>(200, "Usuario eliminado", response));
        } catch (HttpClientErrorException e){
            return handleZitadelError(e);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Error inesperado: " + e.getMessage(), null));
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> desactivate(Long userId) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(obtenerToken());
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<ResponseZitadelDTO> response = restTemplate.exchange(
                    uri+"/v2/users/" + userId + "/deactivate",
                    HttpMethod.POST,
                    entity,
                    ResponseZitadelDTO.class
            );

            return ResponseEntity.ok(
                    new ApiResponse<>(200, "Usuario desactivado correctamente", response.getBody())
            );

        } catch (HttpClientErrorException e) {
            return handleZitadelError(e);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Error inesperado: " + e.getMessage(), null));
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> reactivate(Long userId) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(obtenerToken());
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<ResponseZitadelDTO> response = restTemplate.exchange(
                    uri+"/v2/users/" + userId + "/reactivate",
                    HttpMethod.POST,
                    entity,
                    ResponseZitadelDTO.class
            );

            return ResponseEntity.ok(
                    new ApiResponse<>(200, "Usuario activado correctamente", response.getBody())
            );

        } catch (HttpClientErrorException e) {
            return handleZitadelError(e);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Error inesperado: " + e.getMessage(), null));
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> getUserById(Long userId) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(obtenerToken());
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<Object> response = restTemplate.exchange(
                    uri+"/v2/users/" + userId, HttpMethod.GET, entity, Object.class
            );

            return ResponseEntity.ok(
                    new ApiResponse<>(200, "Usuario obtenido correctamente", response.getBody())
            );

        } catch (HttpClientErrorException e) {
            return handleZitadelError(e);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Error inesperado: " + e.getMessage(), null));
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> assignRolesToUser(RoleGrantRequest data) {

        String userId = data.getUserId();
        String urlAssign = uri+"/management/v1/users/" + userId + "/grants";

        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(obtenerToken());
        headers.setContentType(MediaType.APPLICATION_JSON);

        try {
            JSONObject payload = new JSONObject();
            payload.put("projectId", proyectId);
            payload.put("roleKeys", new JSONArray(data.getRoleKeys()));

            HttpEntity<String> assignEntity = new HttpEntity<>(payload.toString(), headers);
            ResponseEntity<Object> assignResp = restTemplate.exchange(urlAssign, HttpMethod.POST, assignEntity, Object.class);

            return ResponseEntity.ok(new ApiResponse<>(200, "Rol(es) asignado(s) correctamente", assignResp.getBody()));

        } catch (HttpClientErrorException e) {
            String body = e.getResponseBodyAsString();

            if (e.getStatusCode() == HttpStatus.CONFLICT && body.contains("User grant already exists")) {
                try {
                    String urlSearch = uri+"/management/v1/users/grants/_search";

                    JSONObject searchPayload = new JSONObject();
                    JSONArray queries = new JSONArray();
                    JSONObject userIdQuery = new JSONObject();
                    userIdQuery.put("userId", userId);

                    JSONObject queryWrapper = new JSONObject();
                    queryWrapper.put("userIdQuery", userIdQuery);
                    queries.put(queryWrapper);

                    searchPayload.put("queries", queries);

                    HttpEntity<String> searchEntity = new HttpEntity<>(searchPayload.toString(), headers);
                    ResponseEntity<String> response = restTemplate.exchange(urlSearch, HttpMethod.POST, searchEntity, String.class);
                    JSONArray results = new JSONObject(response.getBody()).optJSONArray("result");

                    String grantIdToUpdate = null;

                    if (results != null) {
                        for (int i = 0; i < results.length(); i++) {
                            JSONObject grant = results.getJSONObject(i);
                            if (proyectId.equals(grant.optString("projectId"))) {
                                grantIdToUpdate = grant.optString("id");
                                break;
                            }
                        }
                    }

                    if (grantIdToUpdate == null) {
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ApiResponse<>(400, "No se pudo encontrar grant existente para actualizar", null));
                    }
                    String updateUrl = uri+"/management/v1/users/" + userId + "/grants/" + grantIdToUpdate;

                    JSONObject updatePayload = new JSONObject();
                    updatePayload.put("projectId", proyectId);
                    updatePayload.put("roleKeys", new JSONArray(data.getRoleKeys()));

                    HttpEntity<String> updateEntity = new HttpEntity<>(updatePayload.toString(), headers);
                    ResponseEntity<Object> updateResp = restTemplate.exchange(updateUrl, HttpMethod.PUT, updateEntity, Object.class);

                    return ResponseEntity.ok(new ApiResponse<>(200, "Roles actualizados correctamente", updateResp.getBody()));

                } catch (HttpClientErrorException updateEx) {
                    String updateBody = updateEx.getResponseBodyAsString();
                    if (updateEx.getStatusCode() == HttpStatus.BAD_REQUEST &&
                            updateBody.contains("User grant has not been changed")) {
                        return ResponseEntity.ok(new ApiResponse<>(200, "Rol(es) ya estaban asignados. Nada que actualizar.", null));
                    } else {
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(new ApiResponse<>(500, "Error al actualizar grant existente", null));
                    }
                } catch (Exception ex) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(new ApiResponse<>(500, "Error inesperado al actualizar grant", null));
                }
            }

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

    @Override
    public ResponseEntity<ApiResponse<Object>> createUserBD(AppUserRequest request) {
        try {

            appUserService.insertarAppUserConRoles(
                    request.getId(),
                    request.getOfficeId(),
                    request.getStaffId(),
                    request.getUsername(),
                    request.getFirstname(),
                    request.getLastname(),
                    request.getRoleIds()
            );
            ApiResponse<Object> response = new ApiResponse<>(200, "Usuario creado correctamente", null);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            ApiResponse<Object> response = new ApiResponse<>(500, "Error al crear usuario: " + e.getMessage(), null);
            return ResponseEntity.status(500).body(response);
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> getDatosExtraUsuario(String userId) {
        try {

            Map<String, Object> datos = appUserService.obtenerDatosUsuarioPorId(userId);

            ApiResponse<Object> response = new ApiResponse<>(200, "Datos extra del usuario obtenidos correctamente", datos);
            return ResponseEntity.ok(response);

        } catch (EmptyResultDataAccessException e) {
            ApiResponse<Object> response = new ApiResponse<>(404, "Usuario no encontrado", null);
            return ResponseEntity.status(404).body(response);

        } catch (Exception e) {
            ApiResponse<Object> response = new ApiResponse<>(500, "Error interno: " + e.getMessage(), null);
            return ResponseEntity.status(500).body(response);
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> updateRolesToUser(RoleGrantRequest data){
        try {
            assignRolesToUser(data);
            appUserService.actualizarRoles(data);
            ApiResponse<Object> response = new ApiResponse<>(200, "Datos extra del usuario obtenidos correctamente", null);
            return ResponseEntity.ok(response);

        } catch (EmptyResultDataAccessException e) {
            ApiResponse<Object> response = new ApiResponse<>(404, "Usuario no encontrado", null);
            return ResponseEntity.status(404).body(response);

        } catch (Exception e) {
            ApiResponse<Object> response = new ApiResponse<>(500, "Error interno: " + e.getMessage(), null);
            return ResponseEntity.status(500).body(response);
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> updateOfficeAndStaffToUser(OfficeUpdateRequest data) {
        try {
            appUserService.actualizarOficinaYStaff(data);
            return ResponseEntity.ok(new ApiResponse<>(200, "Office y staff actualizados correctamente", null));
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(404).body(new ApiResponse<>(404, "Usuario no encontrado", null));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(new ApiResponse<>(500, "Error interno: " + e.getMessage(), null));
        }
    }











}
