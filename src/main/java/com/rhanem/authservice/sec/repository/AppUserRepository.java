package com.rhanem.authservice.sec.repository;


import com.rhanem.authservice.sec.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {

    AppUser findByUsername(String usrname);
}
