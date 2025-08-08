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
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;

public class ZitadelTokenValidator {

    private final JwtDecoder jwtDecoder;

    public ZitadelTokenValidator(String issuerUri) {
        this.jwtDecoder = JwtDecoders.fromIssuerLocation(issuerUri);
    }

    public Jwt validate(String token) {
        try {
            return jwtDecoder.decode(token);
        } catch (JwtException e) {
            throw new RuntimeException("Invalid JWT Token: " + e.getMessage(), e);
        }
    }
}
