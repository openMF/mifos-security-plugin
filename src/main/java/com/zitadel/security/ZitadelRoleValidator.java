package com.zitadel.security;

import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Map;

public class ZitadelRoleValidator {

    private static final String CLAIM_NAME = "urn:zitadel:iam:org:project:roles";

    public static boolean hasRole(Jwt jwt, String expectedRole) {
        Object rolesClaim = jwt.getClaims().get(CLAIM_NAME);

        if (rolesClaim instanceof Map<?, ?> map) {
            for (Object orgEntry : map.values()) {
                if (orgEntry instanceof Map<?, ?> innerMap) {
                    for (Object roleValue : innerMap.values()) {
                        if (expectedRole.equals(roleValue)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

}

