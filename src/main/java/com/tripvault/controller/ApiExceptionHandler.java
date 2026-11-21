package com.tripvault.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

/**
 * Turns exceptions into safe, consistent JSON error responses (RFC 9457 "problem details").
 *
 * Security: clients get a short generic message. Stack traces, SQL errors, class names and the
 * rejected input values are NEVER sent back - they would help an attacker map the system
 * (e.g. confirm a SQL injection point). Unexpected errors are logged server-side only.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    /** @Valid @RequestBody failed: report which fields are wrong, not what was sent. */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail invalidBody(MethodArgumentNotValidException ex) {
        List<String> errors = ex.getBindingResult().getAllErrors().stream()
                .map(e -> (e instanceof org.springframework.validation.FieldError fe ? fe.getField() : e.getObjectName())
                        + ": " + e.getDefaultMessage())
                .toList();
        return problem(HttpStatus.BAD_REQUEST, "Validation failed", errors);
    }

    /** Constraint on a @RequestParam / @PathVariable failed. */
    @ExceptionHandler(HandlerMethodValidationException.class)
    public ProblemDetail invalidParameter(HandlerMethodValidationException ex) {
        List<String> errors = ex.getParameterValidationResults().stream()
                .flatMap(r -> r.getResolvableErrors().stream()
                        .map(e -> r.getMethodParameter().getParameterName() + ": " + e.getDefaultMessage()))
                .toList();
        return problem(HttpStatus.BAD_REQUEST, "Validation failed", errors);
    }

    /** Malformed JSON or wrong types (e.g. an invalid date). */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ProblemDetail unreadable(HttpMessageNotReadableException ex) {
        return problem(HttpStatus.BAD_REQUEST, "Malformed request body", List.of());
    }

    /** Expected business errors thrown by the service (404 Not Found, ...). */
    @ExceptionHandler(ResponseStatusException.class)
    public ProblemDetail status(ResponseStatusException ex) {
        HttpStatus status = HttpStatus.valueOf(ex.getStatusCode().value());
        return problem(status, ex.getReason() != null ? ex.getReason() : status.getReasonPhrase(), List.of());
    }

    /** Anything unexpected: log the details internally, return a generic 500. */
    @ExceptionHandler(Exception.class)
    public ProblemDetail unexpected(Exception ex) {
        log.error("Unhandled error", ex);
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "An internal error occurred", List.of());
    }

    private static ProblemDetail problem(HttpStatus status, String detail, List<String> errors) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status, detail);
        if (!errors.isEmpty()) {
            pd.setProperty("errors", errors);
        }
        return pd;
    }
}
