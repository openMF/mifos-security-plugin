package org.apache.fineract.plugins.zitadel.security.service;


import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.apache.fineract.infrastructure.core.domain.FineractPlatformTenant;
import org.apache.fineract.infrastructure.core.service.ThreadLocalContextUtil;
import org.apache.fineract.infrastructure.core.service.tenant.TenantDetailsService;
import org.apache.fineract.plugins.zitadel.security.api.NoRolesAssignedException;
import org.apache.fineract.plugins.zitadel.security.api.dto.*;
import org.apache.fineract.plugins.zitadel.security.api.repository.AppUserService;
import org.apache.fineract.plugins.zitadel.security.api.repository.PermissionService;
import org.apache.fineract.plugins.zitadel.security.api.response.ApiResponse;
import org.apache.fineract.plugins.zitadel.security.api.response.ApiResponsePass;
import org.apache.fineract.plugins.zitadel.security.api.service.TokenMapper;
import org.json.JSONArray;
import org.json.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
public class ApiServiceImp implements ApiService{


    private final RestTemplate restTemplate = new RestTemplate();

    @Autowired
    AppUserService appUserService;

    @Autowired
    PermissionService permissionService;

    @Autowired
    private TokenMapper tokenMapper;


    @Value("${fineract.plugin.oidc.project.id}")
    private String proyectId;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String url;

    @Value("${fineract.plugin.oidc.scope}")
    private String scopetoken;

    @Value("${fineract.plugin.oidc.service-user.client-id}")
    private String clientId;

    @Value("${fineract.plugin.oidc.service-user.client-secret}")
    private String client_secret;

    @Value("${fineract.plugin.oidc.project.grant-id}")
    private String projectGrantId;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String uri;

    @Value("${fineract.plugin.oidc.frontend-url}")
    private String urlfront;

    @Value("${fineract.plugin.oidc.webapp.client-id}")
    private String CLIENT_ID;

    @Value("${fineract.plugin.oidc.opaquetoken.client-id}")
    private String PROJECT_ID;

    @Autowired
    private TenantDetailsService tenantDetailsService;

    private void setTenantFromSecurityContext() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) authentication;
            Jwt token = jwtAuth.getToken();
            String tenantIdentifier = token.getClaimAsString("tenantIdentifier");

            if (tenantIdentifier != null && ThreadLocalContextUtil.getTenant() == null) {
                FineractPlatformTenant tenant = tenantDetailsService.loadTenantById(tenantIdentifier);
                ThreadLocalContextUtil.setTenant(tenant);
            }
        }
    }








    @Override
    public ResponseEntity<ApiResponse<Object>> getRoles() {
        try {

            String url = uri+"/management/v1/projects/" + proyectId + "/roles/_search";
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(obtenerToken());
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

    @Override
    public ResponseEntity<ApiResponse<Object>> createRol(RoleRequest data) {
        try {
            String url = uri+"/management/v1/projects/" + proyectId + "/roles";
            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(obtenerToken());
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
            headers.setBearerAuth(obtenerToken());
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
            headers.setBearerAuth(obtenerToken());
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

            ResponseEntity<Map> response = restTemplate.postForEntity(url.concat("/oauth/v2/token"), request, Map.class);

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
                    .url(url.concat("/management/v1/users/human"))
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
            if (ThreadLocalContextUtil.getTenant() == null) {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (authentication instanceof JwtAuthenticationToken jwtAuth) {
                    Jwt token = jwtAuth.getToken();
                    String tenantIdentifier = token.getClaimAsString("tenantIdentifier");
                    if (tenantIdentifier != null) {
                        FineractPlatformTenant tenant = tenantDetailsService.loadTenantById(tenantIdentifier);
                        ThreadLocalContextUtil.setTenant(tenant);
                    } else {
                        throw new IllegalStateException("tenantIdentifier no encontrado en el token.");
                    }
                } else {
                    throw new IllegalStateException("Autenticación no es de tipo JwtAuthenticationToken.");
                }
            }
            appUserService.insertarAppUserConRoles(
                    request.getId(),
                    request.getOfficeId(),
                    request.getStaffId(),
                    request.getUsername(),
                    request.getFirstname(),
                    request.getLastname(),
                    request.getRoleIds()
            );

            return ResponseEntity.ok(new ApiResponse<>(200, "Usuario creado correctamente", null));
        } catch (Exception e) {
            return ResponseEntity.status(500)
                    .body(new ApiResponse<>(500, "Error al crear usuario: " + e.getMessage(), null));
        }
    }




    @Override
    public ResponseEntity<ApiResponse<Object>> getDatosExtraUsuario(String userId) {
        try {

            if (ThreadLocalContextUtil.getTenant() == null) {
                FineractPlatformTenant tenant = tenantDetailsService.loadTenantById("default"); // o el tenant que uses
                ThreadLocalContextUtil.setTenant(tenant);
            }

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

    @Override
    public ResponseEntity<ApiResponse<UserDetailsDTO>> mapToken(Map<String, Object> tokenPayload) {


        ApiResponse<UserDetailsDTO> response = new ApiResponse<>();

        try {
            if (!tokenPayload.containsKey("access_token")) {
                response.setStatus(400);
                response.setMsg("The 'access_token' field is missing from the payload.");
                response.setObject(null);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
            }

            UserDetailsDTO userDetails = tokenMapper.mapTokenToUserDetails(tokenPayload);

            response.setStatus(200);
            response.setMsg("Full user");
            response.setObject(userDetails);
            return ResponseEntity.ok(response);

        } catch (NoRolesAssignedException e) {
            response.setStatus(403);
            response.setMsg(e.getMessage());
            response.setObject(null);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);

        } catch (Exception ex) {
            response.setStatus(500);
            response.setMsg("Unexpected error: " + ex.getMessage());
            response.setObject(null);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    @Override
    public ResponseEntity<?> getToken(Map<String, String> payload) {
        try {
            String code = payload.get("code");
            String codeVerifier = payload.get("code_verifier");

            // Construir cuerpo correctamente
            String requestBody = "grant_type=authorization_code"
                    + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                    + "&redirect_uri=" + URLEncoder.encode(urlfront + "/callback", StandardCharsets.UTF_8)
                    + "&client_id=" + URLEncoder.encode(CLIENT_ID, StandardCharsets.UTF_8)
                    + "&code_verifier=" + URLEncoder.encode(codeVerifier, StandardCharsets.UTF_8)
                    + "&scope=" + URLEncoder.encode("openid profile email offline_access urn:zitadel:iam:org:project:321191693166617589:roles", StandardCharsets.UTF_8);

            HttpClient client = HttpClient.newHttpClient();

            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(uri + "/oauth/v2/token"))  // Asegúrate que `uri` sea tu dominio: https://plugin-auth-ofrdfj.us1.zitadel.cloud
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            // Validar el código HTTP
            if (response.statusCode() != 200) {
                return ResponseEntity.status(response.statusCode()).body("Error de autenticación: " + response.body());
            }

            // Convertir JSON a Map
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> tokenData = mapper.readValue(response.body(), new TypeReference<>() {});

            return ResponseEntity.ok(tokenData);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error al obtener el token");
        }
    }

    @Override
    public ResponseEntity<ApiResponse<UserDetailsDTO>> userDetails(Map<String, String> tokenMap) {
        String token = tokenMap.get("token");
        UserDetailsDTO userDetails = new UserDetailsDTO();

        if (token == null || token.isEmpty()) {
            return ResponseEntity.ok(new ApiResponse<>(500, "asd", null));
        }

        try {
            HttpClient client = HttpClient.newHttpClient();
            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(uri+"/oidc/v1/userinfo"))
                    .header("Authorization", "Bearer " + token)
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiResponse<>(500, "asdgvhvh", null));
            }

            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> userInfo = objectMapper.readValue(response.body(), new TypeReference<>() {});

            Map<?, ?> rolesId = (Map<?, ?>) userInfo.get("urn:zitadel:iam:org:project:roles");
            List<String> roleNames1 = rolesId.keySet().stream()
                    .map(Object::toString)
                    .collect(Collectors.toList());


            List<RoleDTO> roleDTOS = permissionService.obtenerRoles(roleNames1);
            List<String> permisosDesdeBD = permissionService.obtenerPermisosDesdeRoles(roleNames1);

            userDetails.setUsername(userInfo.get("name").toString());
            userDetails.setUserId(Long.parseLong(userInfo.get("sub").toString()));

            //userDetails.setBase64EncodedAuthenticationKey("bWlmb3M6cGFzc3dvcmQ");
            userDetails.setAuthenticated(true);
            userDetails.setOfficeId(1);
            userDetails.setOfficeName("office_name");
            userDetails.setRoles(roleDTOS);
            userDetails.setPermissions(permisosDesdeBD);
            userDetails.setShouldRenewPassword(false);
            userDetails.setTwoFactorAuthenticationRequired(false);

            return ResponseEntity.ok(new ApiResponse<>(200, "ok", userDetails));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiResponse<>(500, "asd", null));
        }
    }

    @Override
    public ResponseEntity<String> getProjectRoles() {
        String token = getAccessTokenFromSecurityContext();
        String roles = getRolesFromZitadel(token, PROJECT_ID);
        return ResponseEntity.ok(roles);
    }

    public String getAccessTokenFromSecurityContext() {
        BearerTokenAuthentication auth = (BearerTokenAuthentication) SecurityContextHolder.getContext().getAuthentication();
        return auth.getToken().getTokenValue(); // El token JWT original
    }

    public String getRolesFromZitadel(String accessToken, String projectId) {
        String url = uri+"/management/v1/projects/" + projectId + "/roles";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        HttpEntity<Void> entity = new HttpEntity<>(headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);

        return response.getBody();
    }
}
