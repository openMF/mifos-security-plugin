package com.zitadel.security.service.user.roles;

import java.util.List;

public class RoleGrantRequest {
    private String userId;
    private List<String> roleKeys;


    public List<String> getRoleKeys() {
        return roleKeys;
    }

    public void setRoleKeys(List<String> roleKeys) {
        this.roleKeys = roleKeys;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }


}
