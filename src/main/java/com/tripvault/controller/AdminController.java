package com.tripvault.controller;

import com.tripvault.dto.AdminTripView;
import com.tripvault.service.TripService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Admin-only API for support staff.
 *
 * Protected TWICE (defense in depth):
 *  1. URL rule in SecurityConfig:  /api/admin/** -> hasRole("ADMIN")
 *  2. @PreAuthorize on the class:  still enforced if the URL rules are ever changed by mistake.
 *
 * Even admins only see MASKED passport numbers (least privilege): a phished admin account
 * still cannot leak full passport numbers.
 */
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final TripService tripService;

    public AdminController(TripService tripService) {
        this.tripService = tripService;
    }

    @GetMapping("/trips")
    public List<AdminTripView> allTrips() {
        return tripService.allTrips();
    }
}
