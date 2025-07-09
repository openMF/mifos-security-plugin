 package com.zitadel.security.api.repository;


import com.zitadel.security.api.dto.RoleDTO;
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
