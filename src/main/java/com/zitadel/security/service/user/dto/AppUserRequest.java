package com.zitadel.security.service.user.dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Data
@Getter
@Setter
public class AppUserRequest {
    private String id;
    private String officeId;
    private String staffId;
    private String username;
    private String firstname;
    private String lastname;
    private List<String> roleIds;

}
