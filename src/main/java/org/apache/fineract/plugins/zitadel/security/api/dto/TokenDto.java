package org.apache.fineract.plugins.zitadel.security.api.dto;

import lombok.Data;

@Data
public class TokenDto {
    private String access_token;
    private int expires_in;
    private int refresh_expires_in;
    private String refresh_token;
    private String token_type;
    private int not_before_policy;
    private String session_state;
    private String id_token;
}
