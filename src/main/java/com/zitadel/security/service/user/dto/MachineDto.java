package com.zitadel.security.service.user.dto;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class MachineDto {
    private String name;
    private String description;
    private boolean hasSecret;
}
