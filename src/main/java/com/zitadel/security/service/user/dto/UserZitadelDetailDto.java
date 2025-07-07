package com.zitadel.security.service.user.dto;

import lombok.Data;

@Data
public class UserZitadelDetailDto {
    private String sequence;
    private String creationDate;
    private String changeDate;
    private String resourceOwner;
}
