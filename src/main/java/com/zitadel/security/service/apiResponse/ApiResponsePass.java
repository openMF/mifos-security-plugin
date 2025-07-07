package com.zitadel.security.service.apiResponse;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ApiResponsePass {
    private int status;
    private String message;

    public ApiResponsePass() {}

    public ApiResponsePass(int status, String message) {
        this.status = status;
        this.message = message;
    }

}
