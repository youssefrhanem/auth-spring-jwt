package com.rhanem.authservice.sec.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;


@Entity
@Data @NoArgsConstructor @AllArgsConstructor
public class AppUser {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;
    // LAZY : si je charge un oject usr apartire de la base de donnes
    // il ne va pas charger auto les role de ce utilisateur saufe si aue jai besoine des role
    @ManyToMany(fetch = FetchType.EAGER) //EAGER:  des aue je charge user jai les roles de ce user and add new ArrayList<>()
    private Collection<AppRole> appRole = new ArrayList<>();
}
