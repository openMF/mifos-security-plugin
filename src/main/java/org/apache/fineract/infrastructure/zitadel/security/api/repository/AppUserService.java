package org.apache.fineract.infrastructure.zitadel.security.api.repository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.apache.fineract.infrastructure.core.exception.PlatformDataIntegrityException;
import org.apache.fineract.infrastructure.core.service.ThreadLocalContextUtil;
import org.apache.fineract.infrastructure.core.service.database.DatabasePasswordEncryptor;
import org.apache.fineract.infrastructure.security.service.PlatformSecurityContext;
import org.apache.fineract.infrastructure.zitadel.security.api.dto.AppUserRequest;
import org.apache.fineract.infrastructure.zitadel.security.api.dto.OfficeUpdateRequest;
import org.apache.fineract.infrastructure.zitadel.security.api.dto.RoleGrantRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.env.Environment;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class AppUserService {

    private static final Logger logger = LoggerFactory.getLogger(AppUserService.class);

    private final JdbcTemplate jdbcTemplate;
    private final DatabasePasswordEncryptor databasePasswordEncryptor;
    private final Environment environment;
    private final PlatformSecurityContext context;
    private String SCHEMAPOSTGRES = "public";

    public AppUserService(
            final PlatformSecurityContext context,
            final @Qualifier("dataSource") DataSource tenantDataSource,
            final DatabasePasswordEncryptor databasePasswordEncryptor,
            final Environment environment
        ) {
        this.context = context;
        this.databasePasswordEncryptor = databasePasswordEncryptor;
        this.environment = environment;
        this.jdbcTemplate = new JdbcTemplate(tenantDataSource);
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
            throw new RuntimeException("Could not get database type", e);
        }
        return dbProductName.contains("postgresql") ? SCHEMAPOSTGRES : tenant.getConnection().getSchemaName();
    }

    public String resolverOfficeId(String userKey) {
        final String schema = getSchema();
        final String key = (userKey == null) ? null : userKey.trim();

        if (key == null || key.isEmpty()) {
            logger.warn("[resolverOfficeId] empty userKey");
            return null;
        }

        String sql = """
                SELECT u.office_id
                FROM %s.m_appuser u
                WHERE u.id = ? OR u.username_zitadel = ?
                LIMIT 1
            """.formatted(schema);

        Long asLong = null;
        try { asLong = Long.valueOf(key); } catch (NumberFormatException ignore) {}

        Long finalAsLong = asLong;
        String officeId = jdbcTemplate.query(sql, ps -> {
            if (finalAsLong != null) {
                ps.setLong(1, finalAsLong);
            } else {
                ps.setNull(1, java.sql.Types.BIGINT);
            }
            ps.setString(2, key);
        }, rs -> rs.next() ? String.valueOf(rs.getLong(1)) : null);


        return officeId;
    }

    public Map<String, Object> getUserDataById(String userKey) {
        final String schema = getSchema();

        String officeIdStr = resolverOfficeId(userKey);


        if (officeIdStr == null || officeIdStr.isBlank()) {
            throw new EmptyResultDataAccessException("No office_id found for userKey:" + userKey, 1);
        }

        Long officeId;
        try {
            officeId = Long.valueOf(officeIdStr);
        } catch (NumberFormatException nfe) {
            throw new PlatformDataIntegrityException("error.msg.office.id.not.numeric",
                    "office_id is not numeric:" + officeIdStr);
        }

        boolean isNumeric;
        Long userIdLong = null;
        try { userIdLong = Long.valueOf(userKey.trim()); isNumeric = true; }
        catch (Exception e) { isNumeric = false; }

        String whereUser = isNumeric ? "u.id = ?" : "u.username_zitadel = ?";
        String sql = """
        SELECT u.office_id, u.staff_id, u.username_zitadel, u.firstname, u.lastname,
               r.id AS role_id, r.name AS role_name, r.description AS role_description
        FROM %s.m_appuser u
        JOIN %s.m_office o ON o.id = u.office_id
        LEFT JOIN %s.m_appuser_role ur ON u.id = ur.appuser_id
        LEFT JOIN %s.m_role r ON ur.role_id = r.id
        WHERE %s
          AND o.id = ?
    """.formatted(schema, schema, schema, schema, whereUser);

        List<Map<String, Object>> filas = isNumeric
                ? jdbcTemplate.queryForList(sql, userIdLong, officeId)
                : jdbcTemplate.queryForList(sql, userKey.trim(), officeId);

        if (filas.isEmpty() && isNumeric) {
            String sql2 = """
            SELECT u.office_id, u.staff_id, u.username_zitadel, u.firstname, u.lastname,
                   r.id AS role_id, r.name AS role_name, r.description AS role_description
            FROM %s.m_appuser u
            JOIN %s.m_office o ON o.id = u.office_id
            LEFT JOIN %s.m_appuser_role ur ON u.id = ur.appuser_id
            LEFT JOIN %s.m_role r ON ur.role_id = r.id
            WHERE u.username_zitadel = ?
              AND o.id = ?
        """.formatted(schema, schema, schema, schema);

            filas = jdbcTemplate.queryForList(sql2, userKey.trim(), officeId);
        }
        filas.forEach(System.out::println);

        if (filas.isEmpty()) {
            throw new EmptyResultDataAccessException(1);
        }

        Map<String, Object> resultado = new HashMap<>(filas.get(0));
        List<Map<String, Object>> roles = filas.stream()
                .filter(f -> f.get("role_id") != null)
                .map(f -> Map.of(
                        "id", f.get("role_id"),
                        "name", f.get("role_name"),
                        "description", f.get("role_description")
                ))
                .toList();
        resultado.put("roles", roles);
        return resultado;
    }

    public void insertAppUserWithRoles(AppUserRequest request) {
        List<String> roleIds = request.getRoleIds();
        String schema = getSchema();

        String insertUserSql =
        schema.contains(SCHEMAPOSTGRES) ?
                """
                    INSERT INTO %s.m_appuser
                    (id, office_id, staff_id, username, username_zitadel, firstname, lastname, password, email,
                    firsttime_login_remaining, nonexpired, nonlocked, nonexpired_credentials, enabled)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, true, true, true, true, true)
                """.formatted(schema)
                :
                """
                    INSERT INTO %s.m_appuser
                    (id, office_id, staff_id, username, username_zitadel, firstname, lastname, password, email,
                    firsttime_login_remaining, nonexpired, nonlocked, nonexpired_credentials, enabled)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 1, 1, 1)
                """.formatted(schema);

        jdbcTemplate.update(
                insertUserSql,
                schema.contains(SCHEMAPOSTGRES) ? Long.parseLong(request.getId()) : request.getId(),
                schema.contains(SCHEMAPOSTGRES) ? Long.parseLong(request.getOfficeId()) : request.getOfficeId(),
                (request.getStaffId() == null || request.getStaffId().isBlank()) ? null : request.getStaffId(),
                schema.contains(SCHEMAPOSTGRES) ? Long.parseLong(request.getId()) : request.getId(),
                request.getUsername(),
                request.getFirstname(),
                request.getLastname(),
                "",
                ""
        );

        String insertRoleSql = """
            INSERT INTO %s.m_appuser_role (appuser_id, role_id)
            VALUES (?, ?)
        """.formatted(schema);

        if (roleIds != null) {
            for (String roleId : roleIds) {
                jdbcTemplate.update(insertRoleSql,
                        schema.contains(SCHEMAPOSTGRES) ? Long.parseLong(request.getId()) : request.getId(),
                        schema.contains(SCHEMAPOSTGRES) ? Long.parseLong(roleId) : roleId
                    );
            }
        }

        logger.info("User {} inserted with roles {}", request.getId(), roleIds);
    }

    public void updateUserData(String id, String usernameZitadel, String firstname, String lastname) {
        String schema = getSchema();
        String sql = """
                UPDATE %s.m_appuser
                SET username_zitadel = ?,
                    firstname = ?,
                    lastname = ?
                WHERE id = ?
            """.formatted(schema);

        int filas = jdbcTemplate.update(sql,
                usernameZitadel,
                firstname,
                lastname,
                schema.contains(SCHEMAPOSTGRES) ? Long.parseLong(id) : id
        );
        if (filas == 0) {
            throw new RuntimeException("No user found with the provided ID: " + id);
        }
    }

    public void deleteUserWithRoles(String id) {
        String schema = getSchema();

        String deleteRolesSql = """
            DELETE FROM %s.m_appuser_role
            WHERE appuser_id = ?
        """.formatted(schema);
        jdbcTemplate.update(deleteRolesSql, schema.contains(SCHEMAPOSTGRES) ? Long.parseLong(id) : id);

        String deleteUserSql = """
            DELETE FROM %s.m_appuser
            WHERE id = ?
        """.formatted(schema);
        int filas = jdbcTemplate.update(deleteUserSql, schema.contains(SCHEMAPOSTGRES) ? Long.parseLong(id) : id);
        if (filas == 0) {
            throw new EmptyResultDataAccessException("No user found with the ID:" + id, 1);
        }
    }

    public void updateRoles(RoleGrantRequest data) {
        String schema = getSchema();
        String userId = data.getUserId();
        List<String> nuevosRoles = data.getRoleKeys();

        String deleteSql = """
            DELETE FROM %s.m_appuser_role
            WHERE appuser_id = ?
        """.formatted(schema);
        jdbcTemplate.update(deleteSql, schema.contains(SCHEMAPOSTGRES) ? Long.parseLong(userId) : userId);

        if (nuevosRoles != null && !nuevosRoles.isEmpty()) {
            String insertSql = """
                INSERT INTO %s.m_appuser_role (appuser_id, role_id)
                VALUES (?, ?)
            """.formatted(schema);
            for (String roleId : nuevosRoles) {
                jdbcTemplate.update(insertSql,
                        schema.contains(SCHEMAPOSTGRES) ? Long.parseLong(userId) : userId,
                        schema.contains(SCHEMAPOSTGRES) ? Long.parseLong(roleId) : roleId
                );
            }
        }
    }

    public void updateOfficeAndStaff(OfficeUpdateRequest data) {
        String schema = getSchema();
        String sql = """
            UPDATE %s.m_appuser
            SET office_id = ?, staff_id = ?
            WHERE id = ?
        """.formatted(schema);

        Object officeId = null;
        Object staffId = null;
        Object userId;

        if (schema.contains(SCHEMAPOSTGRES)) {
            officeId = (data.getOfficeId() != null) ? Long.parseLong(data.getOfficeId()) : null;
            staffId = (data.getStaffId() != null) ? Long.parseLong(data.getStaffId()) : null;
            userId = (data.getUserId() != null) ? Long.parseLong(data.getUserId()) : null;
        } else {
            officeId = data.getOfficeId();
            staffId = data.getStaffId();
            userId = data.getUserId();
        }

        int filas = jdbcTemplate.update(sql, officeId, staffId, userId);
        if (filas == 0) {
            throw new EmptyResultDataAccessException("User with id not found: " + data.getUserId(), 1);
        }
    }

    public boolean existsById(String id) {
        String schema = getSchema();
        String sql = """
            SELECT COUNT(*) FROM %s.m_appuser WHERE id = ?
        """.formatted(schema);
        Integer count = jdbcTemplate.queryForObject(sql, Integer.class, schema.contains(SCHEMAPOSTGRES) ? Long.parseLong(id) : id);
        return count != null && count > 0;
    }

    public boolean existsColumn(String tableName, String columnName) {
        String schema = getSchema();
        String sql = """
            SELECT COUNT(*) 
            FROM INFORMATION_SCHEMA.COLUMNS 
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ?
        """;
        Integer count = jdbcTemplate.queryForObject(sql, Integer.class, schema, tableName, columnName);
        return count != null && count > 0;
    }

}
