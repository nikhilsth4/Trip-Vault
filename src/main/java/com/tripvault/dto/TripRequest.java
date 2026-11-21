package com.tripvault.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.FutureOrPresent;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

/**
 * Input DTO for creating a trip. Bean Validation rejects bad input with HTTP 400 before any
 * code touches the database.
 *
 *  - Allow-list patterns (only the characters we expect) instead of trying to block "bad"
 *    characters like quotes. This is defense in depth: the real SQL-injection protection is the
 *    parameterized queries in TripRepository.
 *  - There is deliberately NO owner field: the owner always comes from the logged-in session.
 */
public record TripRequest(

        @NotBlank
        @Size(max = 100)
        @Pattern(regexp = "^[\\p{L}][\\p{L} ,.'-]*$",
                 message = "may contain only letters, spaces and , . ' -")
        String destination,

        @NotNull
        @FutureOrPresent
        LocalDate departureDate,

        @NotNull
        LocalDate returnDate,

        @NotBlank
        @Pattern(regexp = "^[A-Za-z0-9]{6,9}$",
                 message = "must be 6-9 letters or digits")
        String passportNumber
) {

    /** Cross-field rule: you cannot come back before you leave. */
    @JsonIgnore
    @AssertTrue(message = "returnDate must be on or after departureDate")
    public boolean isReturnOnOrAfterDeparture() {
        return departureDate == null || returnDate == null || !returnDate.isBefore(departureDate);
    }
}
