package com.twofactorauthentication.service;

import com.twofactorauthentication.controller.signup.DTO.SignupResponse;
import com.twofactorauthentication.entity.AppUserDetail;
import com.twofactorauthentication.repository.RoleRepository;
import com.twofactorauthentication.repository.UserRepository;
import com.twofactorauthentication.shared.enums.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jboss.aerogear.security.otp.Totp;
import org.jboss.aerogear.security.otp.api.Base32;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.HashSet;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    private final PasswordEncoder passwordEncoder;

    public SignupResponse addNewUser(String username, String password, boolean totp) {
        if (userRepository.getUserByUsername(username) != null) {
            return new SignupResponse(SignupResponse.Status.USERNAME_TAKEN);
        }

        if (totp) {
            String secret = Base32.random();
            AppUserDetail appUserDetail = new AppUserDetail();
            appUserDetail.setUsername(username);
            password = passwordEncoder.encode(password);
            appUserDetail.setPassword(password);
            appUserDetail.setSecret(secret);
            appUserDetail.setEnabled(false);
            appUserDetail.setRoleEntities(new HashSet<>(Arrays.asList(this.roleRepository.findByName(Role.ROLE_USER.toString()))));
            this.userRepository.save(appUserDetail);
            return new SignupResponse(SignupResponse.Status.OK, username, secret);
        }

        AppUserDetail appUserDetail = new AppUserDetail();
        appUserDetail.setUsername(username);
        password = passwordEncoder.encode(password);
        appUserDetail.setPassword(password);
        appUserDetail.setEnabled(true);
        appUserDetail.setSecret(null);
        appUserDetail.setRoleEntities(new HashSet<>(Arrays.asList(this.roleRepository.findByName(Role.ROLE_USER.toString()))));
        this.userRepository.save(appUserDetail);

        return new SignupResponse(SignupResponse.Status.OK);
    }

    public boolean signUpConfirmSecret(String username, String code) {
        AppUserDetail appUserDetail = this.userRepository.getUserByUsername(username);
        if (appUserDetail != null) {
            String secret = appUserDetail.getSecret();
            Totp totp = new Totp(secret);
            if (totp.verify(code)) {
                appUserDetail.setEnabled(true);
                this.userRepository.save(appUserDetail);
                return true;
            }
        }
        return false;
    }

}
