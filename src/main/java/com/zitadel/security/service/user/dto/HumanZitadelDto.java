package com.zitadel.security.service.user.dto;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class HumanZitadelDto {
    private ProfileZitadelDto profile;
    private EmailZitadelDto email;
    private PhoneZitadelDto phone;
    private String passwordChanged;
}
