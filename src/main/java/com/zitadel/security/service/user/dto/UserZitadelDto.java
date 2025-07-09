package com.zitadel.security.service.user.dto;

import lombok.Data;
import lombok.ToString;

import java.util.List;

@Data
@ToString
public class UserZitadelDto {
    private String id;
    private DetailsDto details;
    private String state;
    private String userName;
    private List<String> loginNames;
    private String preferredLoginName;
    private MachineDto machine;
    private HumanZitadelDto human;
}
