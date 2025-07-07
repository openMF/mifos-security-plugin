package com.zitadel.security.api.dto;


import lombok.Data;

import java.util.List;

@Data
public class UserDetailsDTO {

    private String username;
    private Long userId;
    private String base64EncodedAuthenticationKey;
    private String accessToken;
    private boolean authenticated;
    private int officeId;
    private String officeName;
    private List<RoleDTO> roles;
    private List<String> permissions;
    private boolean shouldRenewPassword;
    private boolean isTwoFactorAuthenticationRequired;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getBase64EncodedAuthenticationKey() {
        return base64EncodedAuthenticationKey;
    }

    public void setBase64EncodedAuthenticationKey(String base64EncodedAuthenticationKey) {
        this.base64EncodedAuthenticationKey = base64EncodedAuthenticationKey;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }

    public int getOfficeId() {
        return officeId;
    }

    public void setOfficeId(int officeId) {
        this.officeId = officeId;
    }

    public String getOfficeName() {
        return officeName;
    }

    public void setOfficeName(String officeName) {
        this.officeName = officeName;
    }

    public List<RoleDTO> getRoles() {
        return roles;
    }

    public void setRoles(List<RoleDTO> roles) {
        this.roles = roles;
    }

    public List<String> getPermissions() {
        return permissions;
    }

    public void setPermissions(List<String> permissions) {
        this.permissions = permissions;
    }

    public boolean isShouldRenewPassword() {
        return shouldRenewPassword;
    }

    public void setShouldRenewPassword(boolean shouldRenewPassword) {
        this.shouldRenewPassword = shouldRenewPassword;
    }

    public boolean isTwoFactorAuthenticationRequired() {
        return isTwoFactorAuthenticationRequired;
    }

    public void setTwoFactorAuthenticationRequired(boolean twoFactorAuthenticationRequired) {
        isTwoFactorAuthenticationRequired = twoFactorAuthenticationRequired;
    }
}