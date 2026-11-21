package com.tripvault.controller;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Gives API clients (curl, Postman) the CSRF token for their session, so they can call
 * POST/DELETE endpoints. Browsers using the HTML forms get the token automatically
 * (Thymeleaf inserts it into every form). Requires login like every other /api URL.
 *
 * Usage: send the returned token in the header named by "headerName" (X-CSRF-TOKEN).
 */
@RestController
public class CsrfController {

    @GetMapping("/api/csrf")
    public Map<String, String> csrf(CsrfToken token) {
        return Map.of("headerName", token.getHeaderName(), "token", token.getToken());
    }
}
