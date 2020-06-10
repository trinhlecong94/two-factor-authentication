package com.twofactorauthentication.controller.signup;

import com.twofactorauthentication.controller.signup.DTO.SignupResponse;
import com.twofactorauthentication.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.constraints.NotEmpty;


@RestController
public class SignUpController {

    @Autowired
    private UserService userService;

    @PostMapping("/signup")
    public SignupResponse signup(@RequestParam("username") @NotEmpty String username,
                                 @RequestParam("password") @NotEmpty String password,
                                 @RequestParam("totp") boolean totp) {
        return this.userService.addNewUser(username, password, totp);
    }

    @PostMapping("/signup-confirm-secret")
    public boolean signUpConfirmSecret(@RequestParam("username") String username,
                                       @RequestParam("code") @NotEmpty String code) {
        return this.userService.signUpConfirmSecret(username, code);
    }
}
