package com.tripvault.security;

import com.tripvault.model.AppUser;
import com.tripvault.model.Role;
import com.tripvault.repository.AppUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.logout;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Tests the Spring Security configuration: login, BCrypt, lockout, roles, headers, logout. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityConfigTest {

    private static final String PASSWORD = "Correct-Horse-Battery-1";

    @Autowired MockMvc mvc;
    @Autowired AppUserRepository users;
    @Autowired PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        users.deleteAll();
        users.save(new AppUser("carol", passwordEncoder.encode(PASSWORD), Role.USER));
    }

    private AppUser carol() {
        return users.findByUsername("carol").orElseThrow();
    }

    @Test
    void loginPageIsPublicAndWarnsAboutPhishing() throws Exception {
        mvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("will <strong>never</strong> ask for your")))
                .andExpect(content().string(containsString("name=\"_csrf\"")));   // CSRF token in form
    }

    @Test
    void passwordsAreStoredAsBcryptHashes() {
        String hash = carol().getPasswordHash();
        assertThat(hash).startsWith("$2a$12$").doesNotContain(PASSWORD);
        assertThat(passwordEncoder.matches(PASSWORD, hash)).isTrue();
    }

    @Test
    void validCredentialsLogIn() throws Exception {
        mvc.perform(formLogin().user("carol").password(PASSWORD))
                .andExpect(authenticated().withUsername("carol").withRoles("USER"))
                .andExpect(redirectedUrl("/"));
    }

    @Test
    void wrongPasswordShowsGenericError() throws Exception {
        mvc.perform(formLogin().user("carol").password("wrong"))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void unknownUserGetsSameGenericError() throws Exception {
        mvc.perform(formLogin().user("nobody").password("whatever"))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void accountLocksAfterFiveFailedLogins() throws Exception {
        for (int i = 0; i < 5; i++) {
            mvc.perform(formLogin().user("carol").password("guess-" + i)).andExpect(unauthenticated());
        }
        assertThat(carol().getLockedUntil()).isNotNull();

        // Even the CORRECT password is now refused - a phished or guessed password is useless for 15 min.
        mvc.perform(formLogin().user("carol").password(PASSWORD))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void successfulLoginResetsFailureCounter() throws Exception {
        mvc.perform(formLogin().user("carol").password("wrong-1"));
        mvc.perform(formLogin().user("carol").password("wrong-2"));
        assertThat(carol().getFailedAttempts()).isEqualTo(2);

        mvc.perform(formLogin().user("carol").password(PASSWORD)).andExpect(authenticated());
        assertThat(carol().getFailedAttempts()).isZero();
        assertThat(carol().getLastLoginAt()).isNotNull();
    }

    @Test
    void httpBasicWorksForApiClients() throws Exception {
        mvc.perform(get("/api/trips").with(httpBasic("carol", PASSWORD))).andExpect(status().isOk());
        mvc.perform(get("/api/trips").with(httpBasic("carol", "wrong"))).andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "carol", roles = "USER")
    void regularUserCannotUseAdminApi() throws Exception {
        mvc.perform(get("/api/admin/trips")).andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    void adminCanUseAdminApi() throws Exception {
        mvc.perform(get("/api/admin/trips")).andExpect(status().isOk());
    }

    @Test
    void securityHeadersAreSent() throws Exception {
        mvc.perform(get("/login").secure(true))          // HSTS is only sent over HTTPS
                .andExpect(header().string("Strict-Transport-Security", "max-age=31536000 ; includeSubDomains"))
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"));
    }

    @Test
    @WithMockUser("carol")
    void logoutEndsSession() throws Exception {
        mvc.perform(logout())
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?logout"));
    }
}
