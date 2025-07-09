package com.zitadel.security.service.user.dto;

import lombok.Data;

@Data
public class ProfileZitadelDto {
    private String firstName;
    private String lastName;
    private String nickName;
    private String displayName;
    private String preferredLanguage;
    private String gender;
}
