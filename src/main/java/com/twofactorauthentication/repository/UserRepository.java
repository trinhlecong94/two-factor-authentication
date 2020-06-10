package com.twofactorauthentication.repository;

import com.twofactorauthentication.entity.AppUserDetail;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<AppUserDetail, Long> {
    AppUserDetail getUserByUsername(String username);
}
