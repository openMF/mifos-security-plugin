package com.zitadel.security.service.user.dto;

public class PasswordDTO {
    public String currentPassword;

    public String getCurrentPassword() {
        return currentPassword;
    }

    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
    }

    public NewPassword getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(NewPassword newPassword) {
        this.newPassword = newPassword;
    }

    public NewPassword newPassword;

    public static class NewPassword {
        public String password;

        public boolean isChangeRequired() {
            return changeRequired;
        }

        public void setChangeRequired(boolean changeRequired) {
            this.changeRequired = changeRequired;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public boolean changeRequired;
    }
}

