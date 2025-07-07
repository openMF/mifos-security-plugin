package com.zitadel.security.service.user.dto;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class EmailZitadelDto {
    private String email;
    private boolean isEmailVerified;
}
