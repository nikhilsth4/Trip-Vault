package com.tripvault.dto;

import com.tripvault.model.Trip;

import java.time.LocalDate;

/**
 * Output DTO. The passport number is MASKED, never returned in full - not even to its owner.
 * So an attacker who logs in with phished credentials still cannot harvest passport numbers.
 *
 * Masking rule: a fixed "*****" prefix plus only the last 3 characters. The fixed prefix also
 * hides the real length of the number.
 */
public record TripView(
        Long id,
        String destination,
        LocalDate departureDate,
        LocalDate returnDate,
        String passport
) {
    private static final int VISIBLE_CHARS = 3;
    private static final String MASK = "*****";

    public static TripView of(Trip trip) {
        return new TripView(trip.getId(), trip.getDestination(), trip.getDepartureDate(),
                trip.getReturnDate(), mask(trip.getPassportNumber()));
    }

    static String mask(String passport) {
        if (passport == null || passport.length() <= VISIBLE_CHARS) {
            return MASK;
        }
        return MASK + passport.substring(passport.length() - VISIBLE_CHARS);
    }
}
