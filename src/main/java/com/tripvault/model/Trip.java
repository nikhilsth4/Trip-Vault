package com.tripvault.model;

import com.tripvault.security.PassportEncryptor;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * JPA entity mapped to the TRIPS table.
 *
 * Security design:
 *  - passportNumber is ENCRYPTED AT REST: {@link PassportEncryptor} encrypts it with AES-256-GCM
 *    before every INSERT/UPDATE and decrypts it after every SELECT. The database (and anyone who
 *    dumps it through SQL injection or a stolen backup) only ever sees ciphertext.
 *  - ownerUsername comes from the authenticated session, never from the request body, so a user
 *    cannot create or claim trips for someone else.
 *  - No setters: fields are set through the constructor, so a client cannot change id, owner or
 *    createdAt (prevents "mass assignment").
 *  - The entity is never returned to clients; controllers return a masked DTO (TripView).
 */
@Entity
@Table(name = "trips")
public class Trip {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "owner_username", nullable = false, length = 50, updatable = false)
    private String ownerUsername;

    @Column(name = "destination", nullable = false, length = 100)
    private String destination;

    @Column(name = "departure_date", nullable = false)
    private LocalDate departureDate;

    @Column(name = "return_date", nullable = false)
    private LocalDate returnDate;

    // Ciphertext is longer than the passport: "v1:" + Base64(12-byte IV + data + 16-byte tag).
    @Convert(converter = PassportEncryptor.class)
    @Column(name = "passport_number", nullable = false, length = 255)
    private String passportNumber;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /** Required by JPA. */
    protected Trip() {
    }

    public Trip(String ownerUsername, String destination, LocalDate departureDate,
                LocalDate returnDate, String passportNumber) {
        this.ownerUsername = ownerUsername;
        this.destination = destination;
        this.departureDate = departureDate;
        this.returnDate = returnDate;
        this.passportNumber = passportNumber;
    }

    /** Timestamp is set by the server, never supplied by the client. */
    @PrePersist
    void onCreate() {
        this.createdAt = LocalDateTime.now();
    }

    public Long getId() { return id; }
    public String getOwnerUsername() { return ownerUsername; }
    public String getDestination() { return destination; }
    public LocalDate getDepartureDate() { return departureDate; }
    public LocalDate getReturnDate() { return returnDate; }
    public String getPassportNumber() { return passportNumber; }
    public LocalDateTime getCreatedAt() { return createdAt; }
}
