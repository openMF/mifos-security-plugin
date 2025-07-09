package com.zitadel.security.service.user.dto;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
@Getter
@Setter
public class UpdateUserRequest {
    public String userId;
    public EmailDTO email;
    public PhoneDTO phone;
    public ProfileDTO profile;
    public Password password;
    public String currentPassword;


    public UpdateUserRequest() {}

    @Data
    @Getter
    @Setter
    public static class Password {
        public String password;
        public boolean changeRequired;


        public Password() {
        }
    }



}