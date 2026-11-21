package com.tripvault.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

/**
 * Reacts to every login attempt that Spring Security processes:
 *  - wrong password  -> increase the lockout counter
 *  - success         -> reset the counter
 *  - always          -> write a SECURITY AUDIT log line (who, from which IP, result)
 *
 * The audit log is how a security team spots a phishing campaign in progress: e.g. many
 * failures across different accounts from one IP, or a successful login from an unusual IP.
 * Passwords are never logged.
 */
@Component
public class AuthenticationEventsListener {

    private static final Logger audit = LoggerFactory.getLogger("SECURITY_AUDIT");

    private final LoginAttemptService loginAttempts;

    public AuthenticationEventsListener(LoginAttemptService loginAttempts) {
        this.loginAttempts = loginAttempts;
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        Authentication auth = event.getAuthentication();
        loginAttempts.loginSucceeded(auth.getName());
        audit.info("LOGIN_SUCCESS user={} ip={}", sanitize(auth.getName()), remoteIp(auth));
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent event) {
        Authentication auth = event.getAuthentication();
        if (event instanceof AuthenticationFailureBadCredentialsEvent) {
            loginAttempts.loginFailed(auth.getName());
        }
        audit.warn("LOGIN_FAILURE user={} ip={} reason={}", sanitize(auth.getName()), remoteIp(auth),
                event.getException().getClass().getSimpleName());   // e.g. BadCredentialsException, LockedException
    }

    private static String remoteIp(Authentication auth) {
        return auth.getDetails() instanceof WebAuthenticationDetails details
                ? details.getRemoteAddress() : "unknown";
    }

    /**
     * The username is attacker-controlled input. Strip line breaks so nobody can forge fake
     * log entries (log injection), and cap the length.
     */
    private static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        String clean = value.replaceAll("[\\r\\n\\t]", "_");
        return clean.length() > 50 ? clean.substring(0, 50) + "..." : clean;
    }
}
