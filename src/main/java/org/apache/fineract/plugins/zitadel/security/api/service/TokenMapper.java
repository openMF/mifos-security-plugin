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
package org.apache.fineract.plugins.zitadel.security.api.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.fineract.plugins.zitadel.security.api.dto.RoleDTO;
import org.apache.fineract.plugins.zitadel.security.api.dto.UserDetailsDTO;
import org.apache.fineract.plugins.zitadel.security.api.repository.PermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class TokenMapper {


    @Autowired
    private PermissionService permissionService;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String uri;

    public UserDetailsDTO mapTokenToUserDetails(Map<String, Object> tokenMap) {
        UserDetailsDTO userDetails = new UserDetailsDTO();
        List<String> permisos = new ArrayList<>();

        // Obtener el access token del tokenMap
        String accessToken = (String) tokenMap.getOrDefault("access_token", null);

        if (accessToken == null || accessToken.isEmpty()) {
            throw new RuntimeException("Token nulo o inválido");
        }

        try {
            // Llamada al endpoint userinfo
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest userInfoRequest = HttpRequest.newBuilder()
                    .uri(URI.create(uri + "/oidc/v1/userinfo"))
                    .header("Authorization", "Bearer " + accessToken)
                    .GET()
                    .build();

            HttpResponse<String> userInfoResponse = client.send(userInfoRequest, HttpResponse.BodyHandlers.ofString());

            if (userInfoResponse.statusCode() != 200) {
                throw new RuntimeException("Error al consultar userinfo: HTTP " + userInfoResponse.statusCode());
            }

            // Convertir el JSON de respuesta a un mapa
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> userInfo = mapper.readValue(userInfoResponse.body(), Map.class);

            // Asignar datos básicos
            userDetails.setUsername((String) userInfo.getOrDefault("preferred_username", "unknown"));

            String userId = (String) userInfo.getOrDefault("sub", "0");
            try {
                userDetails.setUserId(Long.parseLong(userId));
            } catch (NumberFormatException ex) {
                userDetails.setUserId(0L); // Valor por defecto si sub no es numérico
            }

            // Roles
            Map<String, Object> rolesMap = (Map<String, Object>) userInfo.get("urn:zitadel:iam:org:project:roles");
            List<String> roleNames = (rolesMap != null)
                    ? rolesMap.keySet().stream().map(Object::toString).collect(Collectors.toList())
                    : Collections.emptyList();

            List<RoleDTO> roleDTOS = permissionService.obtenerRoles(roleNames);
            List<String> permisosDesdeBD = permissionService.obtenerPermisosDesdeRoles(roleNames);

            // Quitar duplicados
            permisos.addAll(permisosDesdeBD);
            Set<String> permisosUnicos = new HashSet<>(permisos);

            // Completar objeto UserDetailsDTO
            userDetails.setAccessToken(accessToken);
            userDetails.setAuthenticated(true);
            userDetails.setOfficeId(1);
            userDetails.setOfficeName("Head Office");
            userDetails.setRoles(roleDTOS);
            userDetails.setPermissions(new ArrayList<>(permisosUnicos));
            userDetails.setShouldRenewPassword(false);
            userDetails.setTwoFactorAuthenticationRequired(false);

            return userDetails;

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Error al procesar el token: " + e.getMessage());
        }
    }




}
