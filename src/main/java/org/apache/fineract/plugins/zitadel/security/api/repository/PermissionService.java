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
package org.apache.fineract.plugins.zitadel.security.api.repository;


import org.apache.fineract.plugins.zitadel.security.api.dto.RoleDTO;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
public class PermissionService {

    private final JdbcTemplate jdbcTemplate;

    public PermissionService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<RoleDTO> obtenerRoles(List<String> roleIds) {
        if (roleIds == null || roleIds.isEmpty()) {
            return Collections.emptyList();
        }

        String inSql = String.join(",", Collections.nCopies(roleIds.size(), "?"));
        String sql = """
        SELECT *
        FROM fineract_default.m_role mr
        WHERE mr.id IN (%s)
        """.formatted(inSql);

        return jdbcTemplate.query(
                sql,
                roleIds.toArray(),
                (rs, rowNum) -> {
                    RoleDTO role = new RoleDTO();
                    role.setId(rs.getLong("id"));
                    role.setName(rs.getString("name"));
                    role.setDescription(rs.getString("description"));
                    return role;
                }
        );
    }

    public List<String> obtenerPermisosDesdeRoles(List<String> roleIds) {
        if (roleIds == null || roleIds.isEmpty()) {
            return Collections.emptyList();
        }

        String inSql = String.join(",", Collections.nCopies(roleIds.size(), "?"));
        String sql = """
            SELECT p.code
            FROM fineract_default.m_role_permission rp
            JOIN fineract_default.m_permission p ON rp.permission_id = p.id
            WHERE rp.role_id IN (%s)
        """.formatted(inSql);
        return jdbcTemplate.query(
                sql,
                roleIds.toArray(),
                (rs, rowNum) -> rs.getString("code")
        );
    }


}
