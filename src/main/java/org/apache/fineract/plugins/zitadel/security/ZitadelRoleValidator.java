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
package org.apache.fineract.plugins.zitadel.security;

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

