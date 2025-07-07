package com.zitadel.security.api.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zitadel.security.api.dto.RoleDTO;
import com.zitadel.security.api.dto.UserDetailsDTO;
import com.zitadel.security.api.repository.PermissionService;
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

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.uri}")
    private String uri;

    public UserDetailsDTO mapTokenToUserDetails(Map<String, Object> tokenMap) {
        UserDetailsDTO userDetails = new UserDetailsDTO();
        List<String> permisos = new ArrayList<>();
        String accessToken = (String) tokenMap.getOrDefault("access_token", null);

        if (accessToken != null) {
            try {
                HttpClient client = HttpClient.newHttpClient();
                HttpRequest userInfoRequest = HttpRequest.newBuilder()
                        .uri(URI.create(uri+"/oidc/v1/userinfo"))
                        .header("Authorization", "Bearer " + accessToken)
                        .GET()
                        .build();

                HttpResponse<String> userInfoResponse = client.send(userInfoRequest, HttpResponse.BodyHandlers.ofString());

                if (userInfoResponse.statusCode() == 200) {
                    ObjectMapper mapper = new ObjectMapper();
                    Map<String, Object> userInfo = mapper.readValue(userInfoResponse.body(), Map.class);

                    userDetails.setUsername((String) userInfo.getOrDefault("preferred_username", null));
                    String userId = (String) userInfo.getOrDefault("sub", null);
                    userDetails.setUserId(Long.parseLong(userId));


                    Map<?, ?> rolesId = (Map<?, ?>) userInfo.get("urn:zitadel:iam:org:project:roles");
                    List<String> roleNames1 = rolesId.keySet().stream()
                            .map(Object::toString)
                            .collect(Collectors.toList());

                    List<RoleDTO> roleDTOS = permissionService.obtenerRoles(roleNames1);
                    List<String> permisosDesdeBD = permissionService.obtenerPermisosDesdeRoles(roleNames1);

                    permisos.addAll(permisosDesdeBD);
                    Set<String> permisosUnicos = new HashSet<>(permisos);

                    userDetails.setAccessToken(accessToken);
                    userDetails.setAuthenticated(true);
                    userDetails.setOfficeId(1);
                    userDetails.setOfficeName("Head Office");
                    userDetails.setRoles(roleDTOS);
                    userDetails.setPermissions(new ArrayList<>(permisosUnicos));
                    userDetails.setShouldRenewPassword(false);
                    userDetails.setTwoFactorAuthenticationRequired(false);
                    return userDetails;
                }

            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException("Error al procesar el token: " + e.getMessage());
            }
        }

        throw new RuntimeException("Token nulo o inválido");
    }



}
