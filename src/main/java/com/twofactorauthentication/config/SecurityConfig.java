package com.twofactorauthentication.config;

import com.codahale.passpol.BreachDatabase;
import com.codahale.passpol.PasswordPolicy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter implements WebMvcConfigurer {

  @Bean
  @Override
  protected AuthenticationManager authenticationManager() throws Exception {
    return authentication -> {
      throw new AuthenticationServiceException("Cannot authenticate " + authentication);
    };
  }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder(16, 32, 8, 1 << 16, 4);
    }

    @Bean
    public PasswordPolicy passwordPolicy() {
        return new PasswordPolicy(BreachDatabase.top100K(), 8, 256);
    }


    @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf(customizer -> customizer.disable()).authorizeRequests(customizer -> {
      customizer
          .antMatchers("/authenticate", "/signin", "/verify-totp",
              "/verify-totp-additional-security", "/signup", "/signup-confirm-secret")
          .permitAll().anyRequest().authenticated();
    }).logout(customizer -> customizer
        .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler()));
  }

	@Override
	public void configure(WebSecurity web) {
		web.ignoring().antMatchers("/", "/assets/**/*", "/svg/**/*", "/*.br", "/*.gz", 
		                           "/*.html", "/*.js", "/*.css", "/*.woff2", "/*.ttf", "/*.eot",
															 "/*.svg", "/*.woff", "/*.ico");
	}

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**").allowedMethods("GET", "POST", "PUT", "DELETE", "PATCH").allowedOrigins("*")
                .allowedHeaders("*");
    }

}
