package com.tripvault.security;

import com.tripvault.repository.AppUserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;

/**
 * Account lockout: after N wrong passwords in a row, the account is locked for a period.
 * Defaults (application.properties): 5 attempts, 15 minutes.
 */
@Service
public class LoginAttemptService {

    private final AppUserRepository users;
    private final int maxFailedAttempts;
    private final Duration lockDuration;

    public LoginAttemptService(AppUserRepository users,
                               @Value("${tripvault.security.max-failed-attempts:5}") int maxFailedAttempts,
                               @Value("${tripvault.security.lock-duration:15m}") Duration lockDuration) {
        this.users = users;
        this.maxFailedAttempts = maxFailedAttempts;
        this.lockDuration = lockDuration;
    }

    @Transactional
    public void loginFailed(String username) {
        users.findByUsername(username).ifPresent(user ->
                user.registerFailedLogin(maxFailedAttempts, lockDuration, LocalDateTime.now()));
    }

    @Transactional
    public void loginSucceeded(String username) {
        users.findByUsername(username).ifPresent(user ->
                user.registerSuccessfulLogin(LocalDateTime.now()));
    }
}
