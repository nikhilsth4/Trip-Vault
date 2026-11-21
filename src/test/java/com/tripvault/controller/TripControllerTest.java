package com.tripvault.controller;

import com.tripvault.model.Trip;
import com.tripvault.repository.TripRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** End-to-end tests of the REST API through the full Spring MVC + Spring Security stack. */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class TripControllerTest {

    @Autowired MockMvc mvc;
    @Autowired TripRepository repository;

    private Trip bobTrip;
    private final LocalDate start = LocalDate.now().plusDays(10);

    @BeforeEach
    void setUp() {
        repository.deleteAll();
        repository.save(new Trip("alice", "Rome", start, start.plusDays(3), "N1234567"));
        bobTrip = repository.save(new Trip("bob", "Paris", start, start.plusDays(2), "B7654321"));
    }

    private String body(String destination, LocalDate dep, LocalDate ret, String passport) {
        return """
               {"destination":"%s","departureDate":"%s","returnDate":"%s","passportNumber":"%s"}
               """.formatted(destination, dep, ret, passport);
    }

    @Test
    void anonymousUserIsRejected() throws Exception {
        mvc.perform(get("/api/trips")).andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser("alice")
    void userSeesOnlyOwnTripsWithMaskedPassport() throws Exception {
        mvc.perform(get("/api/trips"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].destination").value("Rome"))
                .andExpect(jsonPath("$[0].passport").value("*****567"));
    }

    @Test
    @WithMockUser("alice")
    void createReturns201WithMaskedPassportAndNormalizesCase() throws Exception {
        mvc.perform(post("/api/trips").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("Kathmandu", start, start.plusDays(7), "pa9988776")))
                .andExpect(status().isCreated())
                .andExpect(header().exists("Location"))
                .andExpect(jsonPath("$.passport").value("*****776"))
                .andExpect(jsonPath("$.passportNumber").doesNotExist());

        assertThat(repository.findByOwnerUsernameOrderByDepartureDateAsc("alice"))
                .anyMatch(t -> t.getPassportNumber().equals("PA9988776"));
    }

    @Test
    @WithMockUser("alice")
    void cannotReadOrDeleteAnotherUsersTrip() throws Exception {
        mvc.perform(get("/api/trips/{id}", bobTrip.getId())).andExpect(status().isNotFound());
        mvc.perform(delete("/api/trips/{id}", bobTrip.getId()).with(csrf())).andExpect(status().isNotFound());
        assertThat(repository.existsById(bobTrip.getId())).isTrue();
    }

    @Test
    @WithMockUser("alice")
    void sqlInjectionInQueryParameterIsRejected() throws Exception {
        mvc.perform(get("/api/trips").param("destination", "x' OR '1'='1"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser("alice")
    void invalidInputIsRejectedWithoutEchoingIt() throws Exception {
        mvc.perform(post("/api/trips").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("Rome'; DROP TABLE trips;--", start, start.minusDays(1), "<script>")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors").isArray())
                .andExpect(jsonPath("$.errors.length()").value(3));
        assertThat(repository.count()).isEqualTo(2);
    }

    @Test
    @WithMockUser("alice")
    void postWithoutCsrfTokenIsForbidden() throws Exception {
        mvc.perform(post("/api/trips")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("Rome", start, start.plusDays(1), "N1234567")))
                .andExpect(status().isForbidden());
    }
}
