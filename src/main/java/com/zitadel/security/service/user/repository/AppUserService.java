package com.zitadel.security.service.user.repository;

import com.zitadel.security.service.user.dto.OfficeUpdateRequest;
import com.zitadel.security.service.user.roles.RoleGrantRequest;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class AppUserService {

    private final JdbcTemplate jdbcTemplate;

    public AppUserService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
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

        String insertUserSql = """
            INSERT INTO fineract_default.m_appuser (id,office_id,staff_id,username,username_zitadel,firstname,lastname,password,email,firsttime_login_remaining,nonexpired,nonlocked,nonexpired_credentials,enabled) 
            VALUES (?,?,?,?,?,?,?,'','',1,1,1,1,1)
        """;
        jdbcTemplate.update(insertUserSql, id, officeId, staffId, id, username, firstname, lastname);

        String insertRoleSql =  """
               INSERT INTO fineract_default.m_appuser_role (appuser_id, role_id)
               VALUES (?, ?)
            """;
        for (String roleId : roleIds) {
            jdbcTemplate.update(insertRoleSql, id, roleId);
        }

    }


    public Map<String, Object> obtenerDatosUsuarioPorId(String userId) {
        String sql = """
        SELECT
            u.office_id,
            u.staff_id,
            u.username_zitadel,
            u.firstname,
            u.lastname,
            r.id AS role_id,
            r.name AS role_name,
            r.description AS role_description
        FROM fineract_default.m_appuser u
        LEFT JOIN fineract_default.m_appuser_role ur ON u.id = ur.appuser_id
        LEFT JOIN fineract_default.m_role r ON ur.role_id = r.id
        WHERE u.id = ?
    """;

        List<Map<String, Object>> filas = jdbcTemplate.queryForList(sql, userId);

        if (filas.isEmpty()) {
            throw new EmptyResultDataAccessException(1);
        }

        Map<String, Object> primera = filas.get(0);

        Map<String, Object> resultado = new HashMap<>();
        resultado.put("officeId", primera.get("office_id"));
        resultado.put("staffId", primera.get("staff_id"));
        resultado.put("username", primera.get("username"));
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
        SET username_zitadel= ?,
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


