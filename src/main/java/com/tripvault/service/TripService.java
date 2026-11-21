package com.tripvault.service;

import com.tripvault.dto.AdminTripView;
import com.tripvault.dto.TripRequest;
import com.tripvault.dto.TripView;
import com.tripvault.model.Trip;
import com.tripvault.repository.TripRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Locale;

/**
 * Business logic between the controller and the repository.
 *
 *  - Every method takes the owner's username (from the authenticated session) and only ever
 *    touches that user's rows.
 *  - @Transactional: each operation is one all-or-nothing database transaction;
 *    readOnly = true for queries blocks accidental writes.
 */
@Service
@Transactional(readOnly = true)
public class TripService {

    private final TripRepository repository;

    public TripService(TripRepository repository) {   // constructor injection
        this.repository = repository;
    }

    public List<TripView> myTrips(String owner, String destination) {
        List<Trip> trips = (destination == null || destination.isBlank())
                ? repository.findByOwnerUsernameOrderByDepartureDateAsc(owner)
                : repository.findByOwnerUsernameAndDestinationIgnoreCaseOrderByDepartureDateAsc(owner, destination.trim());
        return trips.stream().map(TripView::of).toList();
    }

    /** Admin only (enforced in SecurityConfig and with @PreAuthorize). Passports stay masked. */
    @PreAuthorize("hasRole('ADMIN')")
    public List<AdminTripView> allTrips() {
        return repository.findAllByOrderByDepartureDateAsc().stream().map(AdminTripView::of).toList();
    }

    public TripView myTrip(String owner, long id) {
        return TripView.of(findOwnedOrThrow(owner, id));
    }

    @Transactional
    public TripView create(String owner, TripRequest request) {
        Trip trip = new Trip(
                owner,                                                    // from session, not request
                request.destination().trim(),
                request.departureDate(),
                request.returnDate(),
                request.passportNumber().trim().toUpperCase(Locale.ROOT)); // normalize: n1234567 -> N1234567
        return TripView.of(repository.save(trip));                        // encrypted by PassportEncryptor
    }

    @Transactional
    public void delete(String owner, long id) {
        repository.delete(findOwnedOrThrow(owner, id));
    }

    /**
     * Returns 404 (not 403) for trips that exist but belong to someone else, so an attacker
     * cannot even learn which trip ids exist.
     */
    private Trip findOwnedOrThrow(String owner, long id) {
        return repository.findByIdAndOwnerUsername(id, owner)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Trip not found"));
    }
}
