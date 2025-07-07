package com.zitadel.security.api.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zitadel.security.api.NoRolesAssignedException;
import com.zitadel.security.api.dto.RoleDTO;
import com.zitadel.security.api.dto.UserDetailsDTO;
import com.zitadel.security.api.repository.PermissionService;
import com.zitadel.security.service.apiResponse.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class ApiServiceImp implements ApiService {

    @Autowired
    PermissionService permissionService;

    @Autowired
    private TokenMapper tokenMapper;

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.uri}")
    private String uri;

    @Value("${zitadel.url_front}")
    private String url;

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

            HttpClient client = HttpClient.newHttpClient();
            String requestBody = "grant_type=authorization_code"
                    + "&code=" + code
                    + "&redirect_uri="+url+"/callback"
                    + "&client_id=321191693166683125"
                    + "&grant_type=refresh_token expires_in_refresh_token"
                    + "&code_verifier=" + codeVerifier;

            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(uri+"/oauth/v2/token"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

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
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ApiResponse<>(500, "asd", null));
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

            userDetails.setBase64EncodedAuthenticationKey("bWlmb3M6cGFzc3dvcmQ");
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
        String roles = getRolesFromZitadel(token, "320912215601386953");
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
