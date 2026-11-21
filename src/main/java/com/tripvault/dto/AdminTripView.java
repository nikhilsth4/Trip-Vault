package com.tripvault.dto;

import com.tripvault.model.Trip;

import java.time.LocalDate;

/** Admin view of a trip: includes the owner, but the passport is still masked. */
public record AdminTripView(
        Long id,
        String owner,
        String destination,
        LocalDate departureDate,
        LocalDate returnDate,
        String passport
) {
    public static AdminTripView of(Trip trip) {
        return new AdminTripView(trip.getId(), trip.getOwnerUsername(), trip.getDestination(),
                trip.getDepartureDate(), trip.getReturnDate(), TripView.mask(trip.getPassportNumber()));
    }
}
