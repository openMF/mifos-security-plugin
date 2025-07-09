package com.zitadel.security.service.user.dto;

import lombok.Data;
import lombok.ToString;

import java.util.List;

@Data
@ToString
public class ResponseZitadelDTO {
    private DetailsDto details;
    private List<UserZitadelDto> result;
}
