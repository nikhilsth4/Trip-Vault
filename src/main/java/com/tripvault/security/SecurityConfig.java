package com.tripvault.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;

/**
 * Central Spring Security configuration for TripVault.
 *
 * Every HTTP request passes through this filter chain BEFORE it reaches a controller:
 *
 *   1. HTTPS only ........ plain-HTTP requests are redirected to HTTPS (port 8080 -> 8443)
 *   2. Authentication .... form login (browsers) or HTTP Basic (API clients); users and BCrypt
 *                          hashes come from the database via AppUserDetailsService
 *   3. Authorization ..... URL rules (USER vs ADMIN) + @PreAuthorize on methods (defense in depth)
 *   4. CSRF protection ... state-changing requests (POST/DELETE) need a secret per-session token,
 *                          so a malicious site cannot submit requests with the victim's cookie
 *   5. Session security .. new session id after login (stops session fixation), clean logout
 *   6. Security headers .. HSTS, Content-Security-Policy, frame blocking, no-sniff, referrer policy
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity            // enables @PreAuthorize on controller/service methods
public class SecurityConfig {

    /** Content-Security-Policy: the browser may only load scripts/styles/images from this server. */
    private static final String CSP = String.join("; ",
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "img-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",        // forms can only post back to TripVault, not to a phishing site
            "frame-ancestors 'none'");   // no other site may embed TripVault in a frame (clickjacking)

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            @Value("${tripvault.security.require-https:true}") boolean requireHttps) throws Exception {

        // 1. HTTPS only: any request that arrives over plain HTTP gets a redirect to https://
        if (requireHttps) {
            http.redirectToHttps(Customizer.withDefaults());
        }

        http
            // 3. Authorization rules, evaluated top to bottom; anything not listed requires login.
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/error", "/css/**", "/favicon.ico").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").hasAnyRole("USER", "ADMIN")
                .anyRequest().authenticated())

            // 2a. Form login for browsers, using our own page (with an anti-phishing notice).
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/", true)
                .failureUrl("/login?error")      // one generic error: never reveal whether the
                .permitAll())                    // username or the password was wrong

            // 2b. HTTP Basic for API clients (curl, Postman). Safe here because TLS encrypts the header.
            .httpBasic(Customizer.withDefaults())

            // 4. CSRF protection is ON by default in Spring Security; it is deliberately not disabled.
            .csrf(Customizer.withDefaults())

            // 5. Session management
            .sessionManagement(session -> session
                .sessionFixation(fixation -> fixation.changeSessionId()))
            .logout(logout -> logout
                .logoutUrl("/logout")                // POST only (CSRF-protected)
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID"))

            // 6. Security response headers
            .headers(headers -> headers
                .httpStrictTransportSecurity(hsts -> hsts      // browser must use HTTPS for 1 year
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31_536_000))
                .contentSecurityPolicy(csp -> csp.policyDirectives(CSP))
                .frameOptions(frame -> frame.deny())           // legacy clickjacking protection
                .referrerPolicy(ref -> ref.policy(ReferrerPolicy.NO_REFERRER))
                .permissionsPolicyHeader(p -> p.policy("camera=(), microphone=(), geolocation=()")));

        return http.build();
    }

    /**
     * BCrypt with cost factor 12 (2^12 = 4096 hashing rounds, roughly 0.2-0.3 s per hash).
     * Fast enough for a login, far too slow for an attacker brute-forcing a stolen hash table.
     * Each hash includes its own random salt, so identical passwords produce different hashes.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * Publishes login success/failure events. AuthenticationEventsListener uses them for the
     * account lockout counter and the security audit log.
     */
    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher publisher) {
        return new DefaultAuthenticationEventPublisher(publisher);
    }
}
