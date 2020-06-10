package com.twofactorauthentication.controller.signup.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignupResponse {

    public enum Status {
        OK, USERNAME_TAKEN, WEAK_PASSWORD
    }

    private Status status;

    private String username;

    private String secret;

    public SignupResponse(Status status) {
        this(status, null, null);
    }
}
