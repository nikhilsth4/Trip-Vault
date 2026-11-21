package com.tripvault.security;

import com.tripvault.model.AppUser;
import com.tripvault.repository.AppUserRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Tells Spring Security how to load a user from the database during login.
 *
 * Spring Security then compares the submitted password with the stored BCrypt hash itself
 * (DaoAuthenticationProvider + PasswordEncoder), and checks the locked/disabled flags.
 * If the username does not exist, Spring still runs a dummy BCrypt check and reports the same
 * generic "bad credentials" error, so attackers cannot discover valid usernames by timing
 * or by error message.
 */
@Service
public class AppUserDetailsService implements UserDetailsService {

    private final AppUserRepository users;

    public AppUserDetailsService(AppUserRepository users) {
        this.users = users;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = users.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Invalid credentials"));

        return User.withUsername(user.getUsername())
                .password(user.getPasswordHash())
                .roles(user.getRole().name())                        // -> ROLE_USER / ROLE_ADMIN
                .accountLocked(user.isLocked(LocalDateTime.now()))   // lockout after failed logins
                .disabled(!user.isEnabled())
                .build();
    }
}
