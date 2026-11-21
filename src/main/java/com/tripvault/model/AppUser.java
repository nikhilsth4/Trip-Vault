package com.tripvault.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Duration;
import java.time.LocalDateTime;

/**
 * A user account stored in the APP_USERS table.
 *
 * Security design:
 *  - Only a BCrypt HASH of the password is stored, never the password itself. BCrypt is slow and
 *    salted, so a leaked table cannot be reversed with lookup tables and is expensive to brute-force.
 *  - failedAttempts / lockedUntil implement ACCOUNT LOCKOUT: after too many wrong passwords the
 *    account is locked for a while, which stops password-guessing and credential-stuffing attacks
 *    (e.g. an attacker trying passwords harvested by a phishing campaign).
 */
@Entity
@Table(name = "app_users")
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", nullable = false, unique = true, length = 50, updatable = false)
    private String username;

    @Column(name = "password_hash", nullable = false, length = 100)
    private String passwordHash;

    @Enumerated(EnumType.STRING)                 // stored as 'USER' / 'ADMIN', not as a number
    @Column(name = "role", nullable = false, length = 20)
    private Role role;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    protected AppUser() {
    }

    /** @param passwordHash an already-encoded BCrypt hash, never a plain password */
    public AppUser(String username, String passwordHash, Role role) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
    }

    public boolean isLocked(LocalDateTime now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    /** Count a wrong password; lock the account once the limit is reached. */
    public void registerFailedLogin(int maxAttempts, Duration lockDuration, LocalDateTime now) {
        failedAttempts++;
        if (failedAttempts >= maxAttempts) {
            lockedUntil = now.plus(lockDuration);
            failedAttempts = 0;                  // fresh count after the lock expires
        }
    }

    /** A successful login clears the failure counter and any expired lock. */
    public void registerSuccessfulLogin(LocalDateTime now) {
        failedAttempts = 0;
        lockedUntil = null;
        lastLoginAt = now;
    }

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getPasswordHash() { return passwordHash; }
    public Role getRole() { return role; }
    public boolean isEnabled() { return enabled; }
    public int getFailedAttempts() { return failedAttempts; }
    public LocalDateTime getLockedUntil() { return lockedUntil; }
    public LocalDateTime getLastLoginAt() { return lastLoginAt; }
}
