package com.twofactorauthentication.controller.auth;

import com.twofactorauthentication.config.AppUserAuthentication;
import com.twofactorauthentication.config.CustomTotp;
import com.twofactorauthentication.entity.AppUserDetail;
import com.twofactorauthentication.repository.UserRepository;
import com.twofactorauthentication.shared.enums.AuthenticationFlow;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;


@RestController
public class AuthController {

    private final static String USER_AUTHENTICATION_OBJECT = "USER_AUTHENTICATION_OBJECT";

    private final PasswordEncoder passwordEncoder;

    private final String userNotFoundEncodedPassword;

    @Autowired
    private UserRepository userRepository;

    public AuthController(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;

        this.userNotFoundEncodedPassword = this.passwordEncoder
                .encode("userNotFoundPassword");
    }

    @GetMapping("/authenticate")
    public AuthenticationFlow authenticate(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof AppUserAuthentication) {
            return AuthenticationFlow.AUTHENTICATED;
        }
        HttpSession httpSession = request.getSession(false);
        if (httpSession != null) {
            httpSession.invalidate();
        }
        return AuthenticationFlow.NOT_AUTHENTICATED;
    }

    @PostMapping("/signin")
    public ResponseEntity<AuthenticationFlow> login(@RequestParam String username, @RequestParam String password, HttpSession httpSession) {
        AppUserDetail userFromDatabase = this.userRepository.getUserByUsername(username);
        if (userFromDatabase != null) {
            boolean pwMatches = this.passwordEncoder.matches(password,
                    userFromDatabase.getPassword());
            if (pwMatches && userFromDatabase.isEnabled()) {
                AppUserAuthentication userAuthentication = new AppUserAuthentication(userFromDatabase);
                if (isNotBlank(userFromDatabase.getSecret())) {
                    httpSession.setAttribute(USER_AUTHENTICATION_OBJECT, userAuthentication);

                    if (isUserInAdditionalSecurityMode(userFromDatabase.getAppUserId())) {
                        return ResponseEntity.ok().body(AuthenticationFlow.TOTP_ADDITIONAL_SECURITY);
                    }
                    return ResponseEntity.ok().body(AuthenticationFlow.TOTP);
                }
                SecurityContextHolder.getContext().setAuthentication(userAuthentication);
                return ResponseEntity.ok().body(AuthenticationFlow.AUTHENTICATED);
            }
        } else {
            this.passwordEncoder.matches(password, this.userNotFoundEncodedPassword);
        }
        return ResponseEntity.ok().body(AuthenticationFlow.NOT_AUTHENTICATED);
    }

    @PostMapping("/verify-totp")
    public ResponseEntity<AuthenticationFlow> totp(@RequestParam String code,
                                                   HttpSession httpSession) {
        AppUserAuthentication userAuthentication = (AppUserAuthentication) httpSession
                .getAttribute(USER_AUTHENTICATION_OBJECT);
        if (userAuthentication == null) {
            return ResponseEntity.ok().body(AuthenticationFlow.NOT_AUTHENTICATED);
        }
        AppUserDetail detail = (AppUserDetail) userAuthentication.getPrincipal();
        if (isUserInAdditionalSecurityMode(detail.getAppUserId())) {
            return ResponseEntity.ok().body(AuthenticationFlow.TOTP_ADDITIONAL_SECURITY);
        }
        String secret = ((AppUserDetail) userAuthentication.getPrincipal()).getSecret();
        if (isNotBlank(secret) && isNotBlank(code)) {
            CustomTotp totp = new CustomTotp(secret);
            if (totp.verify(code, 2, 2).isValid()) {
                SecurityContextHolder.getContext().setAuthentication(userAuthentication);
                return ResponseEntity.ok().body(AuthenticationFlow.AUTHENTICATED);
            }
            setAdditionalSecurityFlag(detail.getAppUserId());
            return ResponseEntity.ok().body(AuthenticationFlow.TOTP_ADDITIONAL_SECURITY);
        }
        return ResponseEntity.ok().body(AuthenticationFlow.NOT_AUTHENTICATED);
    }

    @PostMapping("/verify-totp-additional-security")
    public ResponseEntity<AuthenticationFlow> verifyTotpAdditionalSecurity(
            @RequestParam String code1, @RequestParam String code2, @RequestParam String code3,
            HttpSession httpSession) {

        AppUserAuthentication userAuthentication = (AppUserAuthentication) httpSession
                .getAttribute(USER_AUTHENTICATION_OBJECT);
        if (userAuthentication == null) {
            return ResponseEntity.ok().body(AuthenticationFlow.NOT_AUTHENTICATED);
        }

        if (code1.equals(code2) || code1.equals(code3) || code2.equals(code3)) {
            return ResponseEntity.ok().body(AuthenticationFlow.NOT_AUTHENTICATED);
        }

        String secret = ((AppUserDetail) userAuthentication.getPrincipal()).getSecret();
        if (isNotBlank(secret) && isNotBlank(code1) && isNotBlank(code2)
                && isNotBlank(code3)) {
            CustomTotp totp = new CustomTotp(secret);
            // check 25 hours into the past and future.
            long noOf30SecondsIntervals = TimeUnit.HOURS.toSeconds(25) / 30;
            List<String> strings = new ArrayList<>();
            strings.add(code1);
            strings.add(code2);
            strings.add(code3);
            CustomTotp.Result result = totp.verify(strings,
                    noOf30SecondsIntervals, noOf30SecondsIntervals);
            if (result.isValid()) {
                if (result.getShift() > 2 || result.getShift() < -2) {
                    httpSession.setAttribute("totp-shift", result.getShift());
                }
                AppUserDetail detail = (AppUserDetail) userAuthentication.getPrincipal();
                clearAdditionalSecurityFlag(detail.getAppUserId());
                httpSession.removeAttribute(USER_AUTHENTICATION_OBJECT);
                SecurityContextHolder.getContext().setAuthentication(userAuthentication);
                return ResponseEntity.ok().body(AuthenticationFlow.AUTHENTICATED);
            }
        }

        return ResponseEntity.ok().body(AuthenticationFlow.NOT_AUTHENTICATED);
    }

    @GetMapping("/totp-shift")
    public String getTotpShift(HttpSession httpSession) {
        Long shift = (Long) httpSession.getAttribute("totp-shift");
        if (shift == null) {
            return null;
        }
        httpSession.removeAttribute("totp-shift");
        StringBuilder out = new StringBuilder();
        long total30Seconds = (int) Math.abs(shift);
        long hours = total30Seconds / 120;
        total30Seconds = total30Seconds % 120;
        long minutes = total30Seconds / 2;
        boolean seconds = total30Seconds % 2 != 0;

        if (hours == 1) {
            out.append("1 hour ");
        } else if (hours > 1) {
            out.append(hours).append(" hours ");
        }

        if (minutes == 1) {
            out.append("1 minute ");
        } else if (minutes > 1) {
            out.append(minutes).append(" minutes ");
        }

        if (seconds) {
            out.append("30 seconds ");
        }

        return out.append(shift < 0 ? "behind" : "ahead").toString();
    }

    private static boolean isNotBlank(String str) {
        return str != null && !str.isEmpty();
    }

    private Boolean isUserInAdditionalSecurityMode(long appUserId) {
        return this.userRepository.getOne(appUserId).isEnabled();
    }

    private void setAdditionalSecurityFlag(long appUserId) {
        AppUserDetail userFromDatabase = this.userRepository.getOne(appUserId);
        userFromDatabase.setEnabled(true);
        userRepository.save(userFromDatabase);
    }

    private void clearAdditionalSecurityFlag(long appUserId) {
        AppUserDetail userFromDatabase = this.userRepository.getOne(appUserId);
        userFromDatabase.setEnabled(false);
        userRepository.save(userFromDatabase);
    }

}
