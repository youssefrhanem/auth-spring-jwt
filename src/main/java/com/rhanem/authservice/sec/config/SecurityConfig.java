package com.rhanem.authservice.sec.config;


import com.rhanem.authservice.sec.filters.JwtAuthenticationFilter;
import com.rhanem.authservice.sec.filters.JwtAuthorizationFilter;
import com.rhanem.authservice.sec.model.AppUser;

import com.rhanem.authservice.sec.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.Collection;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AccountService accountService;


    // comment spring security va cherch les utlisateur et les roles
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                AppUser appUser = accountService.loadUserByUsername(username);


                Collection<GrantedAuthority> authorities = new ArrayList<>();
                appUser.getAppRole().forEach(r-> {
                    authorities.add(new SimpleGrantedAuthority(r.getRoleName()));
                });
                return new User(appUser.getUsername(), appUser.getPassword(),authorities);
            }
        });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
         // je vais utilise une authentification stateless ils vas pas utilise les session
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.headers().frameOptions().disable();

        // http.formLogin(); // affiche login form if user not authenticated

        // http.authorizeRequests().antMatchers(HttpMethod.POST,"/users/**").hasAuthority("ADMIN");
        // http.authorizeRequests().antMatchers(HttpMethod.GET,"/users/**").hasAuthority("USER");

        http.authorizeRequests().antMatchers("/h2-console/**","/refreshToken/**").permitAll();
        http.authorizeRequests().anyRequest().authenticated();

        // Authentication Filter
        http.addFilter(new JwtAuthenticationFilter(authenticationManager()));
        // requestes Filter
        http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
}
