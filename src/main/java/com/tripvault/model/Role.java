package com.tripvault.model;

/** Application roles. Spring Security turns these into authorities ROLE_USER / ROLE_ADMIN. */
public enum Role {
    USER,   // travelers: manage only their own trips
    ADMIN   // support staff: can view all trips (passports still masked)
}
