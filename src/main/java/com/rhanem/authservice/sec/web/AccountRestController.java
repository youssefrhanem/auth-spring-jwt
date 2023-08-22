package com.rhanem.authservice.sec.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rhanem.authservice.sec.model.AppRole;
import com.rhanem.authservice.sec.model.AppUser;


import com.rhanem.authservice.sec.service.AccountService;
import lombok.Data;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {

    private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }

    @PostAuthorize("hasAnyAuthority('USER')")
    @GetMapping(path = "/users")
    public List<AppUser> listUsers() {
        return accountService.listUses();
    }

    @PostAuthorize("hasAnyAuthority('ADMIN')")
    @PostMapping(path = "users")
    public AppUser saveUser(@RequestBody  AppUser appUser){
        return accountService.addNewUser(appUser);
    }

    @PostAuthorize("hasAnyAuthority('ADMIN')")
    @PostMapping(path = "roles")
    public AppRole saveRole(@RequestBody  AppRole appRole){
        return accountService.addNewRole(appRole);
    }

    @PostAuthorize("hasAnyAuthority('ADMIN')")
    @PostMapping(path = "addRoleToUser")
    public void addRoleToUser(@RequestBody  RoleUserForm roleUserForm){
        accountService.addRoleToUser(roleUserForm.getUsername(),roleUserForm.getRoleName());
    }


    // je verifier su le front end si le token est expire
    //si oui je evoyer le refresh token pour effectuer une verfification
    // si nn tt vas bien
    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception{
        String authToken = request.getHeader("Authorization");
        if(authToken != null && authToken.startsWith("Bearer")) {
            try {
                String refreshToken = authToken.substring(7);
                Algorithm algorithm = Algorithm.HMAC256("mySecret1234");
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();

                DecodedJWT decodedJWT =  jwtVerifier.verify(refreshToken); // contain jwt claimes such as username roles
                String username = decodedJWT.getSubject();
                // verfier le black list and roles
                AppUser appUser =  accountService.loadUserByUsername(username);
                // genere le access token
                String jwtAccessToken = JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+5*60*1000))
                        .withIssuer(request.getRequestURI().toString())
                        .withClaim("roles", appUser.getAppRole().stream().map(r -> r.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);

                // envoyer le token

                Map<String,String> idToken = new HashMap<>();
                idToken.put("access-token", jwtAccessToken);
                idToken.put("refresh-token", refreshToken);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);

            }catch (Exception e){
                throw  e;
            }
        } else {
            throw new RuntimeException("Refresh Token required");
        }
    }

    @GetMapping("/profile")
    public AppUser sppUserProfile(Principal  principal){
        return accountService.loadUserByUsername(principal.getName());
    }
}

@Data
class RoleUserForm {

    private String username;
    private String roleName;
}