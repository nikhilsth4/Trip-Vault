package com.tripvault.repository;

import com.tripvault.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/** User accounts. Parameterized query: WHERE username = ? */
public interface AppUserRepository extends JpaRepository<AppUser, Long> {

    Optional<AppUser> findByUsername(String username);
}
