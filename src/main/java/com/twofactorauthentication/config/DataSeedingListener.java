package com.twofactorauthentication.config;

import com.twofactorauthentication.entity.RoleEntity;
import com.twofactorauthentication.entity.AppUserDetail;
import com.twofactorauthentication.repository.RoleRepository;
import com.twofactorauthentication.repository.UserRepository;
import com.twofactorauthentication.shared.enums.Role;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;

@Component
@Configuration
public class DataSeedingListener implements ApplicationListener<ContextRefreshedEvent> {

    @Autowired
    private UserRepository userRepository;


    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${jwt-key}")
    private String signingKey;

    private void addRoleIfMissing(Role role) {
        if (roleRepository.findByName(role.toString()) == null) {
            RoleEntity roleEntity = new RoleEntity();
            roleEntity.setName(role.toString());
            roleRepository.save(roleEntity);
        }
    }

    private void addUserIfMissing(String username, String password, String secret, boolean enabled,  Role... roles) {
        if (userRepository.getUserByUsername(username) == null) {

            Set<RoleEntity> roleIsExists = new HashSet<>();
            for (Role role : roles) {
                roleIsExists.add(roleRepository.findByName(role.toString()));
            }

            userRepository.save(AppUserDetail.builder()
                    .username(username)
                    .password(passwordEncoder.encode(password))
                    .roleEntities(roleIsExists)
                    .enabled(enabled)
                    .secret(secret)
                    .build());
        }
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {

        addRoleIfMissing(Role.ROLE_ADMIN);
        addRoleIfMissing(Role.ROLE_USER);

        addUserIfMissing("user", "user", "LRVLAZ4WVFOU3JBF",true, Role.ROLE_USER);
        addUserIfMissing("admin", "admin", "W4AU5VIXXCPZ3S6T",true, Role.ROLE_USER, Role.ROLE_ADMIN);

    }
}