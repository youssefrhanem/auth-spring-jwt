package com.rhanem.authservice.sec.service;

import com.rhanem.authservice.sec.model.AppRole;
import com.rhanem.authservice.sec.model.AppUser;

import java.util.List;

public interface AccountService {

    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username, String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> listUses();


}
