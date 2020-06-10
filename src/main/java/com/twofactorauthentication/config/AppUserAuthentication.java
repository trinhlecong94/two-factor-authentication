package com.twofactorauthentication.config;

import com.twofactorauthentication.entity.RoleEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class AppUserAuthentication implements Authentication {

  private static final long serialVersionUID = 1L;

  private final com.twofactorauthentication.entity.AppUserDetail userDetail;

  public AppUserAuthentication(com.twofactorauthentication.entity.AppUserDetail userDetail) {
    this.userDetail = userDetail;
  }

  @Override
  public String getName() {
    return this.userDetail.getUsername();
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
      List<GrantedAuthority> authorities
              = new ArrayList<>();
      for (RoleEntity role: this.userDetail.getRoleEntities()) {
          authorities.add(new SimpleGrantedAuthority(role.getName()));

      }
    return authorities;
  }

  @Override
  public Object getCredentials() {
    return null;
  }

  @Override
  public Object getDetails() {
    return null;
  }

  @Override
  public Object getPrincipal() {
    return this.userDetail;
  }

  @Override
  public boolean isAuthenticated() {
    return true;
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    throw new UnsupportedOperationException(
        "this authentication object is always authenticated");
  }

}
