package com.zitadel.security.service.user.dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Data
public class OfficeUpdateRequest {
    private String userId;
    private String officeId;
    private String staffId;

}

