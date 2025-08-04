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
package com.zitadel.security.service.user.repository;

import com.zitadel.security.service.user.dto.OfficeUpdateRequest;
import com.zitadel.security.service.user.roles.RoleGrantRequest;
import org.apache.fineract.infrastructure.core.exception.PlatformDataIntegrityException;
import org.apache.fineract.infrastructure.core.service.ThreadLocalContextUtil;
import org.apache.fineract.infrastructure.security.service.PlatformSecurityContext;
import org.apache.fineract.infrastructure.security.service.DatabasePasswordEncryptor;
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
    private final PlatformSecurityContext context;
    private final DatabasePasswordEncryptor databasePasswordEncryptor;
    private final Environment environment;

    @Autowired
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


    /**
     * Obtiene datos multi-tenant y de usuario actual para filtrar queries o
     * parametrizar conexiones.
     */
    private Map<String, Object> obtenerDatosTenantYUsuario() {
        Map<String, Object> rptParamValues = new HashMap<>();
        try {

            final var tenant = ThreadLocalContextUtil.getTenant();
            final var tenantConnection = tenant.getConnection();

            final AppUser currentUser = context.authenticatedUser();

            final var userHierarchy = currentUser.getOffice().getHierarchy();
            rptParamValues.put("userhierarchy", userHierarchy);

            final var userId = currentUser.getId();
            rptParamValues.put("userid", userId);

            String protocol = toProtocol();
            String tenantUrl = toJdbcUrl(
                    protocol,
                    tenantConnection.getSchemaServer(),
                    tenantConnection.getSchemaServerPort(),
                    tenantConnection.getSchemaName(),
                    tenantConnection.getSchemaConnectionParameters()
            );
            rptParamValues.put("tenantUrl", tenantUrl.trim());

            if (tenantConnection.getSchemaUsername() == null || tenantConnection.getSchemaUsername().isBlank()) {
                rptParamValues.put("username", environment.getProperty("FINERACT_DEFAULT_TENANTDB_UID"));
            } else {
                rptParamValues.put("username", tenantConnection.getSchemaUsername().trim());
            }

            if (tenantConnection.getSchemaPassword() == null || tenantConnection.getSchemaPassword().isBlank()) {
                rptParamValues.put("password", environment.getProperty("FINERACT_DEFAULT_TENANTDB_PWD"));
            } else {
                rptParamValues.put("password", databasePasswordEncryptor.decrypt(tenantConnection.getSchemaPassword()).trim());
            }

            logger.debug("Tenant URL: {} | User Hierarchy: {} | UserId: {}", tenantUrl, userHierarchy, userId);

        } catch (Throwable t) {
            logger.error("Error al obtener datos tenant/usuario:", t);
            throw new PlatformDataIntegrityException("error.msg.reporting.error", t.getMessage());
        }
        return rptParamValues;
    }

    // Helper para protocolo JDBC (ajusta si no es MariaDB/MySQL)
    private String toProtocol() {
        return "jdbc:mariadb";
    }

    // Helper para armar URL JDBC
    private String toJdbcUrl(String protocol, String host, int port, String schema, String params) {
        String baseUrl = String.format("%s://%s:%d/%s", protocol, host, port, schema);
        if (params != null && !params.isBlank()) {
            return baseUrl + "?" + params;
        }
        return baseUrl;
    }

    public void insertarAppUserConRoles(
            String id,
            String officeId,
            String staffId,
            String username,
            String firstname,
            String lastname,
            List<String> roleIds
    ) {
        Map<String, Object> tenantInfo = obtenerDatosTenantYUsuario();

        String insertUserSql = """
            INSERT INTO fineract_default.m_appuser 
            (id, office_id, staff_id, username, username_zitadel, firstname, lastname, password, email, 
             firsttime_login_remaining, nonexpired, nonlocked, nonexpired_credentials, enabled) 
            VALUES (?, ?, ?, ?, ?, ?, ?, '', '', 1, 1, 1, 1, 1)
        """;
        jdbcTemplate.update(insertUserSql, id, officeId, staffId, id, username, firstname, lastname);

        String insertRoleSql =  """
            INSERT INTO fineract_default.m_appuser_role (appuser_id, role_id)
            VALUES (?, ?)
        """;
        for (String roleId : roleIds) {
            jdbcTemplate.update(insertRoleSql, id, roleId);
        }

        logger.info("Usuario {} insertado en tenant {} con roles {}", id, tenantInfo.get("tenantUrl"), roleIds);
    }

    public Map<String, Object> obtenerDatosUsuarioPorId(String userId) {
        Map<String, Object> tenantInfo = obtenerDatosTenantYUsuario();

        String sql = """
            SELECT u.office_id, u.staff_id, u.username_zitadel, u.firstname, u.lastname,
                   r.id AS role_id, r.name AS role_name, r.description AS role_description
            FROM fineract_default.m_appuser u
            LEFT JOIN fineract_default.m_appuser_role ur ON u.id = ur.appuser_id
            LEFT JOIN fineract_default.m_role r ON ur.role_id = r.id
            WHERE u.id = ?
              AND u.office_id LIKE ?
        """;

        List<Map<String, Object>> filas = jdbcTemplate.queryForList(
                sql,
                userId,
                tenantInfo.get("userhierarchy") + "%"
        );

        if (filas.isEmpty()) {
            throw new EmptyResultDataAccessException(1);
        }

        Map<String, Object> primera = filas.get(0);

        Map<String, Object> resultado = new HashMap<>();
        resultado.put("officeId", primera.get("office_id"));
        resultado.put("staffId", primera.get("staff_id"));
        resultado.put("username", primera.get("username_zitadel"));
        resultado.put("firstname", primera.get("firstname"));
        resultado.put("lastname", primera.get("lastname"));

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

    public void actualizarDatosUsuario(
            String id,
            String username,
            String firstname,
            String lastname
    ) {
        String sql = """
            UPDATE fineract_default.m_appuser
            SET username_zitadel = ?,
                firstname = ?,
                lastname = ?
            WHERE id = ?
        """;

        int filasAfectadas = jdbcTemplate.update(sql, username, firstname, lastname, id);

        if (filasAfectadas == 0) {
            throw new RuntimeException("No se encontró ningún usuario con el ID proporcionado: " + id);
        }
    }

    public void eliminarUsuarioConRoles(String id) {
        String deleteRolesSql = """
            DELETE FROM fineract_default.m_appuser_role
            WHERE appuser_id = ?
        """;
        jdbcTemplate.update(deleteRolesSql, id);

        String deleteUserSql = """
            DELETE FROM fineract_default.m_appuser
            WHERE id = ?
        """;
        int filasAfectadas = jdbcTemplate.update(deleteUserSql, id);

        if (filasAfectadas == 0) {
            throw new EmptyResultDataAccessException("No se encontró ningún usuario con el ID: " + id, 1);
        }
    }

    public void actualizarRoles(RoleGrantRequest data) {
        String userId = data.getUserId();
        List<String> nuevosRoles = data.getRoleKeys();

        String deleteSql = """
            DELETE FROM fineract_default.m_appuser_role
            WHERE appuser_id = ?
        """;
        jdbcTemplate.update(deleteSql, userId);

        if (nuevosRoles != null && !nuevosRoles.isEmpty()) {
            String insertSql = """
                INSERT INTO fineract_default.m_appuser_role (appuser_id, role_id)
                VALUES (?, ?)
            """;
            for (String roleId : nuevosRoles) {
                jdbcTemplate.update(insertSql, userId, roleId);
            }
        }
    }

    public void actualizarOficinaYStaff(OfficeUpdateRequest data) {
        String sql = """
            UPDATE fineract_default.m_appuser
            SET office_id = ?, staff_id = ?
            WHERE id = ?
        """;

        int filas = jdbcTemplate.update(sql, data.getOfficeId(), data.getStaffId(), data.getUserId());

        if (filas == 0) {
            throw new EmptyResultDataAccessException("No se encontró el usuario con id: " + data.getUserId(), 1);
        }
    }
}
