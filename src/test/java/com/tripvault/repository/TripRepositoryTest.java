package com.tripvault.repository;

import com.tripvault.model.Trip;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves the two database-level protections:
 *  1. passports are stored encrypted (what a SQL-injection dump would see), and
 *  2. SQL-injection payloads are treated as plain data by the parameterized queries.
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class TripRepositoryTest {

    @Autowired TripRepository repository;
    @Autowired JdbcTemplate jdbc;

    private Trip aliceTrip;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
        LocalDate d = LocalDate.now().plusDays(5);
        aliceTrip = repository.save(new Trip("alice", "Rome", d, d.plusDays(3), "N1234567"));
        repository.save(new Trip("bob", "Paris", d, d.plusDays(2), "B7654321"));
        repository.flush();
    }

    @Test
    void passportIsEncryptedInTheDatabase() {
        // Read the raw column with plain SQL, bypassing JPA - exactly what an attacker dumping the table gets.
        String raw = jdbc.queryForObject(
                "SELECT passport_number FROM trips WHERE id = ?", String.class, aliceTrip.getId());

        assertThat(raw).startsWith("v1:").doesNotContain("N1234567");
        // ...while the application, which holds the key, still reads the real value.
        assertThat(repository.findById(aliceTrip.getId()).orElseThrow().getPassportNumber())
                .isEqualTo("N1234567");
    }

    @Test
    void sqlInjectionPayloadIsTreatedAsData() {
        String payload = "x' OR '1'='1";

        assertThat(repository.findByOwnerUsernameAndDestinationIgnoreCaseOrderByDepartureDateAsc("alice", payload))
                .isEmpty();
        assertThat(repository.findByOwnerUsernameOrderByDepartureDateAsc("alice' OR '1'='1"))
                .isEmpty();
        // The table is intact and nothing leaked across users.
        assertThat(repository.count()).isEqualTo(2);
    }

    @Test
    void lookupsAreScopedToTheOwner() {
        assertThat(repository.findByIdAndOwnerUsername(aliceTrip.getId(), "alice")).isPresent();
        assertThat(repository.findByIdAndOwnerUsername(aliceTrip.getId(), "bob")).isEmpty();
    }
}
