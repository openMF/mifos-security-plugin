package com.zitadel.security.api.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.Map;

@Service
public class TokenIntrospectionService {

    @Value("${spring.security.oauth2.resourceserver.opaquetoken.uri}")
    private static String uri;
    private final String introspectionUrl = uri+"/oauth/v2/introspect";
    private final String clientId = "320912215601386953";
    private final String clientSecret = "SvYVzcVMZ7cUjhlrjicgfez7nxfk66UvxsbNYtmaPzzopn4DnRa3NgDmrfmvOv8J";

    public boolean isTokenActive(String token) {
        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        String auth = clientId + ":" + clientSecret;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "Basic " + encodedAuth);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("token", token);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(introspectionUrl, request, Map.class);
            Boolean active = (Boolean) response.getBody().get("active");
            return active != null && active;
        } catch (Exception e) {
            return false;
        }
    }
}
