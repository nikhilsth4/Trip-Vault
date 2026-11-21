package com.tripvault.controller;

import com.tripvault.dto.TripRequest;
import com.tripvault.dto.TripView;
import com.tripvault.service.TripService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

/**
 * REST API for the logged-in traveler's trips. Served only over HTTPS (see application.properties).
 *
 *   GET    /api/trips                  list my trips
 *   GET    /api/trips?destination=Rome  filter my trips by destination
 *   GET    /api/trips/{id}             one of my trips
 *   POST   /api/trips                  create a trip         -> 201 Created + Location header
 *   DELETE /api/trips/{id}             delete one of my trips -> 204 No Content
 *
 * Security:
 *  - Who the user is comes from Spring Security's {@link Authentication}, never from a request
 *    parameter, so nobody can act as another user by editing the request.
 *  - @Valid / constraint annotations reject bad input with HTTP 400 (see ApiExceptionHandler).
 *  - Responses are TripView DTOs with masked passport numbers; the entity is never exposed.
 */
@RestController
@RequestMapping("/api/trips")
public class TripController {

    private final TripService tripService;

    public TripController(TripService tripService) {
        this.tripService = tripService;
    }

    @GetMapping
    public List<TripView> myTrips(
            @RequestParam(required = false)
            @Size(max = 100)
            @Pattern(regexp = "^[\\p{L}][\\p{L} ,.'-]*$", message = "invalid destination")
            String destination,
            Authentication auth) {
        return tripService.myTrips(auth.getName(), destination);
    }

    @GetMapping("/{id}")
    public TripView myTrip(@PathVariable @Positive long id, Authentication auth) {
        return tripService.myTrip(auth.getName(), id);
    }

    @PostMapping
    public ResponseEntity<TripView> create(@Valid @RequestBody TripRequest request, Authentication auth) {
        TripView created = tripService.create(auth.getName(), request);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}").buildAndExpand(created.id()).toUri();
        return ResponseEntity.created(location).body(created);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable @Positive long id, Authentication auth) {
        tripService.delete(auth.getName(), id);
        return ResponseEntity.noContent().build();
    }
}
