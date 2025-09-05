package org.apache.fineract.infrastructure.zitadel.security.api.repository;

import org.apache.fineract.infrastructure.core.service.ThreadLocalContextUtil;
import org.apache.fineract.infrastructure.zitadel.security.api.dto.RoleDTO;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class PermissionService {

    private final JdbcTemplate jdbcTemplate;
    private String SCHEMAPOSTGRES = "public";

    public PermissionService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    private String getSchema() {
        var tenant = ThreadLocalContextUtil.getTenant();
        if (tenant == null || tenant.getConnection() == null) {
            throw new IllegalStateException("Tenant not set (ThreadLocalContextUtil.getTenant() is null).");
        }
        String dbProductName;
        try (var conn = jdbcTemplate.getDataSource().getConnection()) {
            dbProductName = conn.getMetaData().getDatabaseProductName().toLowerCase();
        } catch (Exception e) {
            throw new RuntimeException("No se pudo obtener el tipo de base de datos", e);
        }
        return dbProductName.contains("postgresql") ? SCHEMAPOSTGRES : tenant.getConnection().getSchemaName();
    }

    public List<RoleDTO> getRoles(List<String> roleIds) {
        if (roleIds == null || roleIds.isEmpty()) {
            return Collections.emptyList();
        }

        final String schema = getSchema();
        String inSql = String.join(",", Collections.nCopies(roleIds.size(), "?"));

        List<Object> params = roleIds.stream()
                .map(roleId -> schema.contains(SCHEMAPOSTGRES) ? Long.parseLong(roleId) : roleId)
                .collect(Collectors.toList());

        String sql = """
            SELECT *
            FROM %s.m_role mr
            WHERE mr.id IN (%s)
        """.formatted(schema, inSql);

        return jdbcTemplate.query(
                sql,
                params.toArray(),
                (rs, rowNum) -> {
                    RoleDTO role = new RoleDTO();
                    role.setId(rs.getLong("id"));
                    role.setName(rs.getString("name"));
                    role.setDescription(rs.getString("description"));
                    return role;
                }
        );
    }

    public List<String> getPermissionsFromRoles(List<String> roleIds) {
        if (roleIds == null || roleIds.isEmpty()) {
            return Collections.emptyList();
        }

        final String schema = getSchema();
        String inSql = String.join(",", Collections.nCopies(roleIds.size(), "?"));

        List<Object> params = roleIds.stream()
                .map(roleId -> schema.contains(SCHEMAPOSTGRES) ? Long.parseLong(roleId) : roleId)
                .collect(Collectors.toList());

        String sql = """
            SELECT p.code
            FROM %s.m_role_permission rp
            JOIN %s.m_permission p ON rp.permission_id = p.id
            WHERE rp.role_id IN (%s)
        """.formatted(schema, schema, inSql);

        return jdbcTemplate.query(
                sql,
                params.toArray(),
                (rs, rowNum) -> rs.getString("code")
        );
    }

    public Map<String, Object> getOfficeByUserId(Long userId) {
        if (userId == null) {
            return Collections.emptyMap();
        }

        final String schema = getSchema();

        String sql = """
            SELECT o.id, o.name
            FROM %s.m_appuser u
            JOIN %s.m_office o ON u.office_id = o.id
            WHERE u.id = ?
        """.formatted(schema, schema);

        return jdbcTemplate.queryForObject(
                sql,
                new Object[]{userId},
                (rs, rowNum) -> {
                    Map<String, Object> office = new HashMap<>();
                    office.put("id", rs.getLong("id"));
                    office.put("name", rs.getString("name"));
                    return office;
                }
        );
    }
}
