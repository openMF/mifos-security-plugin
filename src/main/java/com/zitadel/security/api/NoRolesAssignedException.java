package com.zitadel.security.api;

public class NoRolesAssignedException extends RuntimeException {
    public NoRolesAssignedException(String message) {
        super(message);
    }
}
