package com.tripvault.repository;

import com.tripvault.model.Trip;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

/**
 * Data-access layer for {@link Trip}. Spring Data JPA generates the implementation at runtime
 * from the method names.
 *
 * WHY THIS PREVENTS SQL INJECTION
 * -------------------------------
 * Every method runs as a JDBC PreparedStatement with BOUND PARAMETERS: the SQL text and the
 * user's values are sent to the database separately, so a value can never change the query.
 *
 *   Vulnerable (string concatenation - NEVER do this):
 *     "SELECT * FROM trips WHERE owner_username = '" + user + "' AND destination = '" + dest + "'"
 *     dest = "x' OR '1'='1"  ->  ... AND destination = 'x' OR '1'='1'   (returns EVERY user's trips)
 *
 *   Safe (what Spring Data generates for findByOwnerUsernameAndDestinationIgnoreCase):
 *     SELECT ... FROM trips WHERE owner_username = ? AND upper(destination) = upper(?)
 *     The database searches for a destination literally named  x' OR '1'='1  and finds nothing.
 *
 * WHY THIS PREVENTS IDOR (Insecure Direct Object Reference)
 * --------------------------------------------------------
 * Every query is scoped by ownerUsername. Looking a trip up by id alone (findById) would let a
 * logged-in user read or delete another user's trip just by guessing ids 1, 2, 3...
 */
public interface TripRepository extends JpaRepository<Trip, Long> {

    /** All trips of one user: WHERE owner_username = ? */
    List<Trip> findByOwnerUsernameOrderByDepartureDateAsc(String ownerUsername);

    /** One user's trips to a destination: WHERE owner_username = ? AND upper(destination) = upper(?) */
    List<Trip> findByOwnerUsernameAndDestinationIgnoreCaseOrderByDepartureDateAsc(String ownerUsername,
                                                                                 String destination);

    /** Admin view of all trips (only reachable by ROLE_ADMIN, see AdminController). */
    List<Trip> findAllByOrderByDepartureDateAsc();

    /** A trip only if it belongs to this user: WHERE id = ? AND owner_username = ? */
    Optional<Trip> findByIdAndOwnerUsername(Long id, String ownerUsername);
}
