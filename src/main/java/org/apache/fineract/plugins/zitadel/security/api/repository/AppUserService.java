package org.apache.fineract.plugins.zitadel.security.api.repository;

import org.apache.fineract.infrastructure.core.domain.FineractPlatformTenant;
import org.apache.fineract.infrastructure.core.exception.PlatformDataIntegrityException;
import org.apache.fineract.infrastructure.core.service.ThreadLocalContextUtil;
import org.apache.fineract.infrastructure.core.service.tenant.TenantDetailsService;
import org.apache.fineract.infrastructure.security.service.PlatformSecurityContext;
import org.apache.fineract.infrastructure.core.service.database.DatabasePasswordEncryptor;
import org.apache.fineract.plugins.zitadel.security.api.dto.OfficeUpdateRequest;
import org.apache.fineract.plugins.zitadel.security.api.dto.RoleGrantRequest;
import org.apache.fineract.useradministration.domain.AppUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.env.Environment;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class AppUserService {

    private static final Logger logger = LoggerFactory.getLogger(AppUserService.class);

    private final JdbcTemplate jdbcTemplate;
    private final DatabasePasswordEncryptor databasePasswordEncryptor;
    private final Environment environment;
    private final PlatformSecurityContext context;

    public AppUserService(
            final PlatformSecurityContext context,
            final @Qualifier("dataSource") DataSource tenantDataSource,
            final DatabasePasswordEncryptor databasePasswordEncryptor,
            final Environment environment
    ) {
        this.context = context;
        this.databasePasswordEncryptor = databasePasswordEncryptor;
        this.environment = environment;
        this.jdbcTemplate = new JdbcTemplate(tenantDataSource); // DataSource multi-tenant (rota por contexto)
    }



    private String getSchema() {
        var tenant = ThreadLocalContextUtil.getTenant();
        if (tenant == null || tenant.getConnection() == null) {
            throw new IllegalStateException("Tenant no establecido (ThreadLocalContextUtil.getTenant() es null).");
        }
        return tenant.getConnection().getSchemaName();
    }

    private String toProtocol() { return "jdbc:mariadb"; }

    private String toJdbcUrl(String protocol, String host, int port, String schema, String params) {
        String base = String.format("%s://%s:%d/%s", protocol, host, port, schema);
        return (params != null && !params.isBlank()) ? base + "?" + params : base;
    }


    public String resolverOfficeId(String userKey) {
        final String schema = getSchema();
        final String key = (userKey == null) ? null : userKey.trim();
        logger.debug("[resolverOfficeId] schema={}, userKey='{}'", schema, key);
        if (key == null || key.isEmpty()) {
            logger.warn("[resolverOfficeId] userKey vacío");
            return null;
        }

        // Query única: intenta por id o por username_zitadel
        String sql = """
        SELECT u.office_id
        FROM %s.m_appuser u
        WHERE u.id = ? OR u.username_zitadel = ?
        LIMIT 1
    """.formatted(schema);

        // bindeo robusto: si key no es numérico, setLong a null (usa setNull)
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

        logger.debug("[resolverOfficeId] resultado officeId={}", officeId);
        System.out.println("[resolverOfficeId] schema=" + schema + " key=" + key + " officeId=" + officeId);
        return officeId;
    }



    public Map<String, Object> obtenerDatosUsuarioPorId(String userKey) {
        final String schema = getSchema();


        String officeIdStr = resolverOfficeId(userKey);
        logger.debug("UserKey recibido: {}", userKey);
        logger.debug("OfficeId resuelto: {}", officeIdStr);

        if (officeIdStr == null || officeIdStr.isBlank()) {
            throw new EmptyResultDataAccessException("No se encontró office_id para userKey: " + userKey, 1);
        }

        Long officeId;
        try {
            officeId = Long.valueOf(officeIdStr);
        } catch (NumberFormatException nfe) {
            throw new PlatformDataIntegrityException("error.msg.office.id.not.numeric",
                    "office_id no es numérico: " + officeIdStr);
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

        logger.debug("SQL (pass #1):\n{}", sql);
        logger.debug("Bind (pass #1): user={}, officeId={}", userKey, officeId);

        List<Map<String, Object>> filas = isNumeric
                ? jdbcTemplate.queryForList(sql, userIdLong, officeId)
                : jdbcTemplate.queryForList(sql, userKey.trim(), officeId);

        logger.debug("Filas encontradas (pass #1): {}", filas.size());

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

            logger.debug("SQL (pass #2 fallback por username_zitadel):\n{}", sql2);
            logger.debug("Bind (pass #2): username_zitadel={}, officeId={}", userKey, officeId);

            filas = jdbcTemplate.queryForList(sql2, userKey.trim(), officeId);
            logger.debug("Filas encontradas (pass #2): {}", filas.size());
        }

        System.out.println("=== Resultado crudo de la consulta ===");
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

        System.out.println("=== Resultado final ===");
        System.out.println(resultado);
        logger.debug("Resultado final: {}", resultado);

        return resultado;
    }




    public void insertarAppUserConRoles(
            String id,
            String officeId,
            String staffId,
            String usernameZitadel,
            String firstname,
            String lastname,
            List<String> roleIds
    ) {
        // (opcional) valida tenant activo
        getSchema();

        String schema = getSchema();
        String insertUserSql = """
            INSERT INTO %s.m_appuser
            (id, office_id, staff_id, username, username_zitadel, firstname, lastname, password, email,
             firsttime_login_remaining, nonexpired, nonlocked, nonexpired_credentials, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 1, 1, 1)
        """.formatted(schema);

        jdbcTemplate.update(
                insertUserSql,
                id,
                officeId,
                staffId,
                id,                // username (si así lo quieres)
                usernameZitadel,   // username_zitadel
                firstname,
                lastname,
                "",                // password
                ""                 // email
        );

        String insertRoleSql = """
            INSERT INTO %s.m_appuser_role (appuser_id, role_id)
            VALUES (?, ?)
        """.formatted(schema);

        if (roleIds != null) {
            for (String roleId : roleIds) {
                jdbcTemplate.update(insertRoleSql, id, roleId);
            }
        }

        logger.info("Usuario {} insertado con roles {}", id, roleIds);
    }

    public void actualizarDatosUsuario(String id, String usernameZitadel, String firstname, String lastname) {
        String schema = getSchema();
        String sql = """
            UPDATE %s.m_appuser
            SET username_zitadel = ?,
                firstname = ?,
                lastname = ?
            WHERE id = ?
        """.formatted(schema);

        int filas = jdbcTemplate.update(sql, usernameZitadel, firstname, lastname, id);
        if (filas == 0) {
            throw new RuntimeException("No se encontró ningún usuario con el ID proporcionado: " + id);
        }
    }

    public void eliminarUsuarioConRoles(String id) {
        String schema = getSchema();

        String deleteRolesSql = """
            DELETE FROM %s.m_appuser_role
            WHERE appuser_id = ?
        """.formatted(schema);
        jdbcTemplate.update(deleteRolesSql, id);

        String deleteUserSql = """
            DELETE FROM %s.m_appuser
            WHERE id = ?
        """.formatted(schema);
        int filas = jdbcTemplate.update(deleteUserSql, id);
        if (filas == 0) {
            throw new EmptyResultDataAccessException("No se encontró ningún usuario con el ID: " + id, 1);
        }
    }

    public void actualizarRoles(RoleGrantRequest data) {
        String schema = getSchema();
        String userId = data.getUserId();
        List<String> nuevosRoles = data.getRoleKeys();

        String deleteSql = """
            DELETE FROM %s.m_appuser_role
            WHERE appuser_id = ?
        """.formatted(schema);
        jdbcTemplate.update(deleteSql, userId);

        if (nuevosRoles != null && !nuevosRoles.isEmpty()) {
            String insertSql = """
                INSERT INTO %s.m_appuser_role (appuser_id, role_id)
                VALUES (?, ?)
            """.formatted(schema);
            for (String roleId : nuevosRoles) {
                jdbcTemplate.update(insertSql, userId, roleId);
            }
        }
    }

    public void actualizarOficinaYStaff(OfficeUpdateRequest data) {
        String schema = getSchema();
        String sql = """
            UPDATE %s.m_appuser
            SET office_id = ?, staff_id = ?
            WHERE id = ?
        """.formatted(schema);

        int filas = jdbcTemplate.update(sql, data.getOfficeId(), data.getStaffId(), data.getUserId());
        if (filas == 0) {
            throw new EmptyResultDataAccessException("No se encontró el usuario con id: " + data.getUserId(), 1);
        }
    }



}
