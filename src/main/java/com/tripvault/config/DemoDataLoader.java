package com.tripvault.config;

import com.tripvault.model.AppUser;
import com.tripvault.model.Role;
import com.tripvault.model.Trip;
import com.tripvault.repository.AppUserRepository;
import com.tripvault.repository.TripRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.LocalDate;
import java.util.Base64;

/**
 * Creates demo users and trips at startup (not in the "test" profile).
 *
 *  - Users: alice (USER), bob (USER), admin (ADMIN).
 *  - No password is hard-coded in source code. If DEMO_PASSWORD is set it is used for all demo
 *    users; otherwise a random password is generated per user and printed ONCE in the startup
 *    log (the same approach Spring Boot uses for its default generated password).
 *  - Passwords are stored only as BCrypt hashes; trips are saved through JPA, so their passport
 *    numbers are encrypted exactly like real data. The passport numbers are fictitious.
 */
@Component
@Profile("!test")
public class DemoDataLoader implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoDataLoader.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final AppUserRepository users;
    private final TripRepository trips;
    private final PasswordEncoder passwordEncoder;
    private final String demoPassword;

    public DemoDataLoader(AppUserRepository users, TripRepository trips, PasswordEncoder passwordEncoder,
                          @Value("${tripvault.demo.password:}") String demoPassword) {
        this.users = users;
        this.trips = trips;
        this.passwordEncoder = passwordEncoder;
        this.demoPassword = demoPassword;
    }

    @Override
    public void run(String... args) {
        if (users.count() > 0) {
            return;
        }
        createUser("alice", Role.USER);
        createUser("bob", Role.USER);
        createUser("admin", Role.ADMIN);

        LocalDate today = LocalDate.now();
        trips.save(new Trip("alice", "Kathmandu", today.plusDays(30), today.plusDays(44), "PA1234567"));
        trips.save(new Trip("alice", "Tokyo", today.plusDays(90), today.plusDays(97), "PA1234567"));
        trips.save(new Trip("bob", "Paris", today.plusDays(10), today.plusDays(15), "XB9876543"));
    }

    private void createUser(String username, Role role) {
        boolean generated = demoPassword.isBlank();
        String password = generated ? randomPassword() : demoPassword;
        users.save(new AppUser(username, passwordEncoder.encode(password), role));
        if (generated) {
            log.warn("DEMO ONLY - created user '{}' ({}) with generated password: {}", username, role, password);
        } else {
            log.info("DEMO ONLY - created user '{}' ({}) with the password from DEMO_PASSWORD", username, role);
        }
    }

    private static String randomPassword() {
        byte[] bytes = new byte[12];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);   // 16 random chars
    }
}
