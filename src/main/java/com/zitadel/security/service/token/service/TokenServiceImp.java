package com.zitadel.security.service.token.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.Map;

@Service
public class TokenServiceImp implements TokenService {

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.uri}")
    private String uri;

    @Value("${zitadel.url.front}")
    private String url;

    @Value("${zitadel.web-app.client_id}")
    private String CLIENT_ID;

    @Override
    public ResponseEntity<?> getToken(Map<String, String> payload) {
        try {
            String code = payload.get("code");
            String codeVerifier = payload.get("code_verifier");

            HttpClient client = HttpClient.newHttpClient();
            String requestBody = "grant_type=authorization_code"
                    + "&code=" + code
                    + "&redirect_uri="+url+"/callback"
                    + "&client_id=" +  CLIENT_ID
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

}
