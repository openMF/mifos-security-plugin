package org.apache.fineract.infrastructure.zitadel.security.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.apache.fineract.infrastructure.core.domain.FineractPlatformTenant;
import org.apache.fineract.infrastructure.core.service.ThreadLocalContextUtil;
import org.apache.fineract.infrastructure.core.service.tenant.TenantDetailsService;
import org.apache.fineract.infrastructure.zitadel.security.api.NoRolesAssignedException;
import org.apache.fineract.infrastructure.zitadel.security.api.dto.*;
import org.apache.fineract.infrastructure.zitadel.security.api.repository.AppUserService;
import org.apache.fineract.infrastructure.zitadel.security.api.repository.PermissionService;
import org.apache.fineract.infrastructure.zitadel.security.api.response.ApiResponse;
import org.apache.fineract.infrastructure.zitadel.security.api.response.ApiResponsePass;
import org.apache.fineract.infrastructure.zitadel.security.api.service.TokenMapper;
import org.json.JSONArray;
import org.json.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.EmptyResultDataAccessException;
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
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;


@Slf4j
@Service
public class ApiServiceImp implements ApiService{
    
    private static final Logger logger = LoggerFactory.getLogger(ApiServiceImp.class);


    private final RestTemplate restTemplate = new RestTemplate();

    @Autowired
    AppUserService appUserService;

    @Autowired
    PermissionService permissionService;

    @Autowired
    private TokenMapper tokenMapper;

    @Value("${fineract.plugin.oidc.project.id}")
    private String projectId;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String INSTANCE_URL;

    private final String scopeToken="openid profile email urn:zitadel:iam:org:project:id:zitadel:aud";

    @Value("${fineract.plugin.oidc.service-user.client-id}")
    private String clientId;

    @Value("${fineract.plugin.oidc.service-user.client-secret}")
    private String CLIENT_SECRET;

    @Value("${fineract.plugin.oidc.project.grant-id}")
    private String projectGrantId;

    @Value("${fineract.plugin.oidc.frontend-url}")
    private String frontUrl;

    @Value("${fineract.plugin.oidc.webapp.client-id}")
    private String CLIENT_ID;

    @Value("${fineract.plugin.oidc.opaquetoken.client-id}")
    private String PROJECT_ID;

    @Value("${fineract.default.tenantdb.identifier}")
    private String TENANTDB;

    private final ObjectMapper mapper = new ObjectMapper();
    

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

            String url = INSTANCE_URL+"/management/v1/projects/" + projectId + "/roles/_search";
//            RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(getToken());
            headers.setContentType(MediaType.APPLICATION_JSON);

            JSONObject json = new JSONObject();
            HttpEntity<String> entity = new HttpEntity<>(json.toString(), headers);

            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.POST, entity, Object.class);

            return ResponseEntity.ok(new ApiResponse<>(200, "GET Roles", response.getBody()));

        } catch (HttpClientErrorException e) {
            return handleZitadelError(e);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Unexpected error: " + e.getMessage(), null));
        }

    }

    @Override
    public ResponseEntity<ApiResponse<Object>> createRol(RoleRequest data) {
        try {
            String url = INSTANCE_URL+"/management/v1/projects/" + projectId + "/roles";
            //RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(getToken());
            headers.setContentType(MediaType.APPLICATION_JSON);

            JSONObject json = new JSONObject();
            json.put("roleKey", data.getRoleKey());
            json.put("displayName", data.getDisplayName());
            json.put("group", data.getGroup() != null ? data.getGroup() : "");

            HttpEntity<String> entity = new HttpEntity<>(json.toString(), headers);

            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.POST, entity, Object.class);

            return ResponseEntity.ok(new ApiResponse<>(200, "Successfully created role", response.getBody()));

        } catch (HttpClientErrorException e) {
            return handleZitadelError(e);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Unexpected error: " + e.getMessage(), null));
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> deleteRol(String roleKey) {
        try {
            String url = INSTANCE_URL+"/management/v1/projects/" + projectId + "/roles/" + roleKey;

            //RestTemplate restTemplate = new RestTemplate();

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(getToken());
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<String> entity = new HttpEntity<>(headers);

            ResponseEntity<Object> response = restTemplate.exchange(
                    url,
                    HttpMethod.DELETE,
                    entity,
                    Object.class
            );

            return ResponseEntity.ok(
                    new ApiResponse<>(200, "Successfully deleted role", response.getBody())
            );

        } catch (HttpClientErrorException e) {
            return handleZitadelError(e);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Unexpected error: " + e.getMessage(), null));
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> updateRol(String roleKey, RoleRequest data) {
        try {
            String url = INSTANCE_URL+"/management/v1/projects/" + projectId + "/roles/" + roleKey;

            //RestTemplate restTemplate = new RestTemplate();
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(getToken());
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

            return ResponseEntity.ok(new ApiResponse<>(200, "Role updated successfully", response.getBody()));

        } catch (HttpClientErrorException e) {
            return handleZitadelError(e);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Unexpected error: " + e.getMessage(), null));
        }
    }

    @Override
    public String getToken() {
        try {

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("grant_type", "client_credentials");
            body.add("client_id", clientId);
            body.add("client_secret", CLIENT_SECRET);
            body.add("scope", scopeToken);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            //RestTemplate restTemplate = new RestTemplate();

            ResponseEntity<Map> response = restTemplate.postForEntity(INSTANCE_URL.concat("/oauth/v2/token"), request, Map.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                Map<String, Object> responseBody = response.getBody();
                if (responseBody != null && responseBody.containsKey("access_token")) {
                    return responseBody.get("access_token").toString();
                } else {
                    throw new RuntimeException("Token not found in response");
                }
            } else {
                throw new RuntimeException("Error getting token: " + response.getStatusCode());
            }
        } catch (HttpClientErrorException e) {
            throw new RuntimeException("Error getting Zitadel token", e);
        } catch (Exception e) {
            throw new RuntimeException("Unexpected error getting token", e);
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
                    .url(INSTANCE_URL.concat("/management/v1/users/human"))
                    .post(body)
                    .addHeader("Authorization", "Bearer " + getToken())
                    .addHeader("Content-Type", "application/json")
                    .build();

            Response response = client.newCall(request).execute();

            if (!response.isSuccessful()) {
                String responseBody = response.body() != null ? response.body().string() : "no response body";
                throw new RuntimeException("Error creating user in Zitadel: " + responseBody);
            }

            String responseBody = response.body().string();
            Map<String, Object> responseData = mapper.readValue(responseBody, Map.class);

            return ResponseEntity.ok(new ApiResponse<>(200, "Successfully created user", responseData));

        } catch (Exception e) {
            throw new RuntimeException("Error creating user in Zitadel", e);
        }
    }

    @Override
    public ResponseEntity<ApiResponse<ResponseZitadelDTO>> getUser(String id) {
        //RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getToken());
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<ResponseZitadelDTO> response = restTemplate.exchange(
                    INSTANCE_URL+"/management/v1/users/_search",
                    HttpMethod.POST,
                    entity,
                    ResponseZitadelDTO.class
            );

            ResponseZitadelDTO responseBody = response.getBody();

            if (responseBody != null && responseBody.getResult() != null) {
                List<UserZitadelDto> allUsers = responseBody.getResult();

                if (id == null || id.isEmpty()) {
                    return ResponseEntity.ok(new ApiResponse<>(200, "Users obtained", responseBody));
                }

                List<UserZitadelDto> filteredUsers = allUsers.stream()
                        .filter(user -> id.equals(user.getId()))
                        .collect(Collectors.toList());

                ResponseZitadelDTO filteredResponse = new ResponseZitadelDTO();
                filteredResponse.setDetails(responseBody.getDetails());
                filteredResponse.setResult(filteredUsers);

                return ResponseEntity.ok(new ApiResponse<>(200, "Users obtained", filteredResponse));
            }

            return ResponseEntity.ok(new ApiResponse<>(404, "User not found", null));
        } catch (Exception e) {
            return ResponseEntity.ok(new ApiResponse<>(400, "Error getting user", null));
        }
    }

    @Override
    public String updateUser(UpdateUserRequest req) {
        String baseUrl = INSTANCE_URL + "/v2/users/";
        StringBuilder result = new StringBuilder();

        if (req.email != null) {
            result.append(postRequest(baseUrl + req.userId + "/email", getToken(), req.email));
        }

        if (req.phone != null) {
            result.append(postRequest(baseUrl + req.userId + "/phone", getToken(), req.phone));
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
            result.append(putRequest(url, getToken(), body));
            appUserService.updateUserData(req.userId, req.profile.username, req.profile.givenName, req.profile.familyName);


        }

        return result.toString();
    }

    @Override
    public ResponseEntity<ApiResponsePass> updatePass(Map<String, Object> jsonBody) {
        String baseUrl = INSTANCE_URL + "/v2/users/";
        String userId = (String) jsonBody.get("userId");
        String token = getToken();

        if (userId == null || token == null) {
            ApiResponsePass error = new ApiResponsePass(400, "Required fields are missing: 'userId' or 'token'");
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

            ApiResponsePass success = new ApiResponsePass(response.getStatusCodeValue(), "successful process");
            return ResponseEntity.status(response.getStatusCode()).body(success);

        } catch (HttpStatusCodeException e) {
            ApiResponsePass error = new ApiResponsePass(e.getRawStatusCode(), e.getResponseBodyAsString());
            return ResponseEntity.status(e.getStatusCode()).body(error);
        } catch (Exception e) {
            e.printStackTrace();
            ApiResponsePass error = new ApiResponsePass(500, "Internal Server Error: " + e.getMessage());
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
        //RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getToken());
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<ResponseZitadelDTO> response = restTemplate.exchange(
                    INSTANCE_URL+"/v2/users/" + userId,
                    HttpMethod.DELETE,
                    entity,
                    ResponseZitadelDTO.class
            );
            appUserService.deleteUserWithRoles(userId.toString());
            return ResponseEntity.ok(new ApiResponse<>(200, "Deleted user", response));
        } catch (HttpClientErrorException e){
            return handleZitadelError(e);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Unexpected error: " + e.getMessage(), null));
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> desactivate(Long userId) {
        //RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getToken());
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<ResponseZitadelDTO> response = restTemplate.exchange(
                    INSTANCE_URL+"/v2/users/" + userId + "/deactivate",
                    HttpMethod.POST,
                    entity,
                    ResponseZitadelDTO.class
            );

            return ResponseEntity.ok(
                    new ApiResponse<>(200, "User successfully deactivated", response.getBody())
            );

        } catch (HttpClientErrorException e) {
            return handleZitadelError(e);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Unexpected error: " + e.getMessage(), null));
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> reactivate(Long userId) {
        //RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getToken());
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<ResponseZitadelDTO> response = restTemplate.exchange(
                    INSTANCE_URL+"/v2/users/" + userId + "/reactivate",
                    HttpMethod.POST,
                    entity,
                    ResponseZitadelDTO.class
            );

            return ResponseEntity.ok(
                    new ApiResponse<>(200, "Successfully activated user", response.getBody())
            );

        } catch (HttpClientErrorException e) {
            return handleZitadelError(e);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Unexpected error: " + e.getMessage(), null));
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> getUserById(Long userId) {
        //RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getToken());
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<Object> response = restTemplate.exchange(
                    INSTANCE_URL+"/v2/users/" + userId, HttpMethod.GET, entity, Object.class
            );

            return ResponseEntity.ok(
                    new ApiResponse<>(200, "Successfully obtained user", response.getBody())
            );

        } catch (HttpClientErrorException e) {
            return handleZitadelError(e);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Unexpected error: " + e.getMessage(), null));
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> assignRolesToUser(RoleGrantRequest data) {

        String userId = data.getUserId();
        String urlAssign = INSTANCE_URL+"/management/v1/users/" + userId + "/grants";

        //RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getToken());
        headers.setContentType(MediaType.APPLICATION_JSON);

        try {
            JSONObject payload = new JSONObject();
            payload.put("projectId", projectId);
            payload.put("roleKeys", new JSONArray(data.getRoleKeys()));

            HttpEntity<String> assignEntity = new HttpEntity<>(payload.toString(), headers);
            ResponseEntity<Object> assignResp = restTemplate.exchange(urlAssign, HttpMethod.POST, assignEntity, Object.class);

            return ResponseEntity.ok(new ApiResponse<>(200, "Roles assigned successfully", assignResp.getBody()));

        } catch (HttpClientErrorException e) {
            String body = e.getResponseBodyAsString();

            if (e.getStatusCode() == HttpStatus.CONFLICT && body.contains("User grant already exists")) {
                try {
                    String urlSearch = INSTANCE_URL+"/management/v1/users/grants/_search";

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
                            if (projectId.equals(grant.optString("projectId"))) {
                                grantIdToUpdate = grant.optString("id");
                                break;
                            }
                        }
                    }

                    if (grantIdToUpdate == null) {
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(new ApiResponse<>(400, "Could not find existing grant to update", null));
                    }
                    String updateUrl = INSTANCE_URL+"/management/v1/users/" + userId + "/grants/" + grantIdToUpdate;

                    JSONObject updatePayload = new JSONObject();
                    updatePayload.put("projectId", projectId);
                    updatePayload.put("roleKeys", new JSONArray(data.getRoleKeys()));

                    HttpEntity<String> updateEntity = new HttpEntity<>(updatePayload.toString(), headers);
                    ResponseEntity<Object> updateResp = restTemplate.exchange(updateUrl, HttpMethod.PUT, updateEntity, Object.class);

                    return ResponseEntity.ok(new ApiResponse<>(200, "Roles updated successfully", updateResp.getBody()));

                } catch (HttpClientErrorException updateEx) {
                    String updateBody = updateEx.getResponseBodyAsString();
                    if (updateEx.getStatusCode() == HttpStatus.BAD_REQUEST &&
                            updateBody.contains("User grant has not been changed")) {
                        return ResponseEntity.ok(new ApiResponse<>(200, "Role(s) were already assigned. Nothing to update.", null));
                    } else {
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(new ApiResponse<>(500, "Error updating existing grant", null));
                    }
                } catch (Exception ex) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                            .body(new ApiResponse<>(500, "Unexpected error when updating the grant", null));
                }
            }

            return handleZitadelError(e);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(500, "Unexpected error: " + e.getMessage(), null));
        }
    }

    // TODO: Bad_Request, It handles the consumption error and remains internal depending on the code received, whether it is 5 or 9. If it is different, a BAD_REQUEST is issued directly.
    private ResponseEntity<ApiResponse<Object>> handleZitadelError(HttpClientErrorException e) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> errorJson = mapper.readValue(e.getResponseBodyAsString(), Map.class);

            int code = (int) errorJson.getOrDefault("code", 400);
            String message = (String) errorJson.getOrDefault("message", "Unknown error");
            Object details = errorJson.get("details");

            HttpStatus status = (code == 5) ? HttpStatus.NOT_FOUND : (code == 9) ? HttpStatus.ACCEPTED : HttpStatus.BAD_REQUEST;

            return ResponseEntity.status(status)
                    .body(new ApiResponse<>(code, message, details));

        } catch (Exception parseException) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse<>(400, "Error parsing error message", null));
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
                        throw new IllegalStateException("tenantIdentifier not found in token.");
                    }
                } else {
                    throw new IllegalStateException("Authentication is not of type JwtAuthenticationToken.");
                }
            }
            appUserService.insertAppUserWithRoles(
                    request.getId(),
                    request.getOfficeId(),
                    request.getStaffId(),
                    request.getUsername(),
                    request.getFirstname(),
                    request.getLastname(),
                    request.getRoleIds()
            );

            return ResponseEntity.ok(new ApiResponse<>(200, "Successfully created user", null));
        } catch (Exception e) {
            return ResponseEntity.status(500)
                    .body(new ApiResponse<>(500, "Error creating user: " + e.getMessage(), null));
        }
    }




    @Override
    public ResponseEntity<ApiResponse<Object>> getdataExtraUser(String userId) {
        try {

            if (ThreadLocalContextUtil.getTenant() == null) {
                FineractPlatformTenant tenant = tenantDetailsService.loadTenantById("default");
                ThreadLocalContextUtil.setTenant(tenant);
            }

            Map<String, Object> data = appUserService.getUserDataById(userId);
            ApiResponse<Object> response = new ApiResponse<>(200, "Additional user data obtained successfully", data);
            return ResponseEntity.ok(response);

        } catch (EmptyResultDataAccessException e) {
            ApiResponse<Object> response = new ApiResponse<>(404, "User not found", null);
            return ResponseEntity.status(404).body(response);

        } catch (Exception e) {
            ApiResponse<Object> response = new ApiResponse<>(500, "Unexpected error: " + e.getMessage(), null);
            return ResponseEntity.status(500).body(response);
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> updateRolesToUser(RoleGrantRequest data){
        try {
            assignRolesToUser(data);
            appUserService.updateRoles(data);
            ApiResponse<Object> response = new ApiResponse<>(200, "Additional user data obtained successfully", null);
            return ResponseEntity.ok(response);

        } catch (EmptyResultDataAccessException e) {
            ApiResponse<Object> response = new ApiResponse<>(404, "User not found", null);
            return ResponseEntity.status(404).body(response);

        } catch (Exception e) {
            ApiResponse<Object> response = new ApiResponse<>(500, "Unexpected error: " + e.getMessage(), null);
            return ResponseEntity.status(500).body(response);
        }
    }

    @Override
    public ResponseEntity<ApiResponse<Object>> updateOfficeAndStaffToUser(OfficeUpdateRequest data) {
        try {
            appUserService.updateOfficeAndStaff(data);
            return ResponseEntity.ok(new ApiResponse<>(200, "Office and staff updated successfully", null));
        } catch (EmptyResultDataAccessException e) {
            return ResponseEntity.status(404).body(new ApiResponse<>(404, "User not found", null));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(new ApiResponse<>(500, "Unexpected error: " + e.getMessage(), null));
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
            response.setMsg("User details retrieved successfully");
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

            String redirectUri = frontUrl.replaceAll("/$", "") + "/#/callback";

            String requestBody = "grant_type=authorization_code"
                    + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
                    + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                    + "&client_id=" + URLEncoder.encode(CLIENT_ID, StandardCharsets.UTF_8)
                    + "&code_verifier=" + URLEncoder.encode(codeVerifier, StandardCharsets.UTF_8)
                    + "&scope=" + URLEncoder.encode(
                    "openid profile email offline_access urn:zitadel:iam:org:project:"+projectId+":roles",
                    StandardCharsets.UTF_8);

            HttpClient client = HttpClient.newHttpClient();

            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(INSTANCE_URL + "/oauth/v2/token"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                return ResponseEntity.status(response.statusCode())
                        .body("Authentication error: " + response.body());
            }

            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> tokenData = mapper.readValue(response.body(), new TypeReference<>() {});

            return ResponseEntity.ok(tokenData);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error getting token");
        }
    }


    @Override
    public ResponseEntity<ApiResponse<UserDetailsDTO>> userDetails(Map<String, String> tokenMap) {
        String token = tokenMap.get("token");
        UserDetailsDTO userDetails = new UserDetailsDTO();

        if (token == null || token.isEmpty()) {
    return ResponseEntity.ok(
        new ApiResponse<>(500, "Null authentication token", null)
    );
}


        try {
            HttpClient client = HttpClient.newHttpClient();
            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(INSTANCE_URL+"/oidc/v1/userinfo"))
                    .header("Authorization", "Bearer " + token)
                    .GET()
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
        .body(new ApiResponse<>(400, "Failed to fetch userinfo from OIDC endpoint", null));
}

            ObjectMapper objectMapper = new ObjectMapper();
            Map<String, Object> userInfo = objectMapper.readValue(response.body(), new TypeReference<>() {});

            Map<?, ?> rolesId = (Map<?, ?>) userInfo.get("urn:zitadel:iam:org:project:roles");
            List<String> roleNames1 = rolesId.keySet().stream()
                    .map(Object::toString)
                    .collect(Collectors.toList());


            List<RoleDTO> roleDTOS = permissionService.getRoles(roleNames1);
            List<String> permisosDesdeBD = permissionService.getPermissionsFromRoles(roleNames1);

            userDetails.setUsername(userInfo.get("name").toString());
            userDetails.setUserId(Long.parseLong(userInfo.get("sub").toString()));

            userDetails.setAuthenticated(true);
            userDetails.setOfficeId(1);
            userDetails.setOfficeName("office_name");
            userDetails.setRoles(roleDTOS);
            userDetails.setPermissions(permisosDesdeBD);
            userDetails.setShouldRenewPassword(false);
            userDetails.setTwoFactorAuthenticationRequired(false);

            return ResponseEntity.ok(new ApiResponse<>(200, "ok", userDetails));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiResponse<>(500, "Unexpected error while fetching userinfo", null));
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
        return auth.getToken().getTokenValue();
    }

    public String getRolesFromZitadel(String accessToken, String projectId) {
        String url = INSTANCE_URL+"/management/v1/projects/" + projectId + "/roles";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        HttpEntity<Void> entity = new HttpEntity<>(headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);

        return response.getBody();
    }


    @Override
    public String afterStartup(){
        FineractPlatformTenant tenant = tenantDetailsService.loadTenantById(TENANTDB);
        ThreadLocalContextUtil.setTenant(tenant);

        if (!appUserService.existsColumn("m_appuser", "username_zitadel")) {
            appUserService.addColumn("m_appuser", "username_zitadel");
        }

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(getToken());
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        try {
            ResponseEntity<ResponseZitadelDTO> response = restTemplate.exchange(
                    INSTANCE_URL+"/management/v1/users/_search",
                    HttpMethod.POST,
                    entity,
                    ResponseZitadelDTO.class
            );
            ResponseZitadelDTO responseBody = response.getBody();
            if (responseBody != null && responseBody.getResult() != null) {
                List<UserZitadelDto> allUsers = responseBody.getResult();
                return afterStartupUser(allUsers);
            }
            return "";
        } catch (Exception e) {
            return "ERROR:  "+ e.getMessage();
        }
    }

    public String afterStartupUser(List<UserZitadelDto> allUsers){
        try {
            if (allUsers == null || allUsers.isEmpty()) {
                return "empty list";
            }

            UserZitadelDto lastUser = allUsers.get(allUsers.size() - 1);

            if (appUserService.existsById(lastUser.getId())) {
                return "existing user";
            }

            AppUserRequest request = new AppUserRequest();
            request.setId(lastUser.getId());
            request.setOfficeId("1");
            request.setStaffId(null);
            request.setUsername(lastUser.getUserName());

            if (lastUser.getHuman() != null && lastUser.getHuman().getProfile() != null) {
                request.setFirstname(lastUser.getHuman().getProfile().getFirstName());
                request.setLastname(lastUser.getHuman().getProfile().getLastName());
            } else {
                request.setFirstname("N/A");
                request.setLastname("N/A");
            }

            request.setRoleIds(Arrays.asList("1"));

            appUserService.insertAppUserWithRoles(
                    request.getId(),
                    request.getOfficeId(),
                    request.getStaffId(),
                    request.getUsername(),
                    request.getFirstname(),
                    request.getLastname(),
                    request.getRoleIds()
            );

            return "create user";

        } catch (Exception e) {
            e.printStackTrace();
            return "error: " + e.getMessage();
        }
    }
    
    // helpers ---------------------------------------------------------

    private static String hmacSha256Hex(String data, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static boolean secureCompare(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8),
                                     b.getBytes(StandardCharsets.UTF_8));
    }

    private record Session(String id, Instant creationDate) {}


}
