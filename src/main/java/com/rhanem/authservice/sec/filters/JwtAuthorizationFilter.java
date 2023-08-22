package com.rhanem.authservice.sec.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import static com.rhanem.authservice.sec.util.JWTConstant.AUTH_HEADER;
import static com.rhanem.authservice.sec.util.JWTConstant.SECRET;


// ce filter doive etre sur tout les microservice
public class JwtAuthorizationFilter extends OncePerRequestFilter {


    // method sexecute chaque fois il ya une requete


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/refreshToken")){
            filterChain.doFilter(request,response);
        } else {
            // String authorizationToken = request.getHeader("Authorization");
            String authorizationToken = request.getHeader(AUTH_HEADER);
            if (authorizationToken != null && authorizationToken.startsWith("Bearer ")){
                try {
                    String jwt = authorizationToken.substring(7);
                    Algorithm algorithm = Algorithm.HMAC256(SECRET);
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT =  jwtVerifier.verify(jwt); // contain jwt claimes such as username roles
                    String username = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                    Collection<GrantedAuthority> authorities = new ArrayList<>();
                    for (String role: roles){
                        authorities.add(new SimpleGrantedAuthority(role));
                    }
                    // authentifier lutilisaeur  (username, pswd, role)
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username,null,authorities);
                    // authentifier
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    // je vais lui dire tu peux passer au filter suivant
                    filterChain.doFilter(request,response);
                }catch (Exception e){
                    response.setHeader("error-mesage",e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                }
            } else {
                // si la resource demander necicite une authentification le filter suivante va le bloaue
                // sinon il va vas recevoire le resource demander
                filterChain.doFilter(request,response);
            }
        }
    }
}
