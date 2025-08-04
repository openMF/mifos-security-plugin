/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
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
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
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

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String uri;

    @Value("${fineract.plugin.oidc.frontend-url}")
    private String url;

    @Value("${fineract.plugin.oidc.webapp.client-id}")
    private String CLIENT_ID;

    @Value("${fineract.plugin.oidc.opaquetoken.client-id}")
    private String PROJECT_ID;


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
                    + "&redirect_uri=" + URLEncoder.encode(url + "/callback", StandardCharsets.UTF_8)
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
