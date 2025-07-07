package com.zitadel.security.service.dto;

public class RoleRequest {
    private String roleKey;
    private String displayName;
    private String group;

    public RoleRequest() {
    }

    public RoleRequest(String roleKey, String displayName, String group) {
        this.roleKey = roleKey;
        this.displayName = displayName;
        this.group = group;
    }

    public String getRoleKey() {
        return roleKey;
    }

    public void setRoleKey(String roleKey) {
        this.roleKey = roleKey;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getGroup() {
        return group;
    }

    public void setGroup(String group) {
        this.group = group;
    }
}


