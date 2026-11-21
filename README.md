# TripVault: Secure Trip Booking API

A Spring Boot REST API that gives **secure access to a database over HTTPS on the network**. It was built for a Secure Coding assignment with this scenario: a company is hit by a phishing email pretending to be IT (asking for credentials), and its web application is vulnerable to SQL injection.

Travelers store trips that include a **passport number**. Passport numbers are encrypted in the database with AES-256-GCM and are always masked in API responses (`*****567`).

## Tech stack

- Java 21, Spring Boot 4.2, Maven (wrapper included)
- Spring Security 7, Spring Data JPA (Hibernate 7), Bean Validation
- Thymeleaf (login and home pages)
- H2 in-memory database (PostgreSQL driver included for production)
- Embedded Tomcat with TLS (PKCS12 keystore created with `keytool`)

## Security controls

| Threat | Controls |
|---|---|
| **SQL injection** | Parameterized Spring Data queries only (no string-built SQL); allow-list input validation on every field and query parameter; database constraints; generic error responses with no stack traces or SQL details |
| **Phishing / stolen credentials** | BCrypt (cost 12) password hashes; account lockout after 5 failed logins for 15 minutes; `SECURITY_AUDIT` log of every login with user and IP (log-injection safe); owner-scoped queries so a user only sees their own trips (404 for others); passports masked even for admins; anti-phishing notice on the login page |
| **Data theft from the database** | Passport numbers encrypted with AES-256-GCM (random IV per value, tamper detection); key kept outside the code and database |
| **Network attacks** | HTTPS only on port 8443 with TLS 1.3 and 1.2; HTTP on 8080 redirects to HTTPS; HSTS; Secure, HttpOnly, SameSite=Strict session cookie |
| **Web attacks** | CSRF tokens on all state-changing requests; session fixation protection; Content-Security-Policy, X-Frame-Options DENY, Referrer-Policy, Permissions-Policy |
| **Privilege escalation** | Deny-by-default URL rules; `/api/admin/**` restricted to ADMIN by URL rule and `@PreAuthorize` |

## Getting started (Windows)

### 1. Prerequisites

- JDK 21. If `JAVA_HOME` is not set globally, set it in the PowerShell session:

```powershell
$env:JAVA_HOME = "C:\path\to\jdk-21"
```

### 2. Create the secrets (one time)

Both scripts write to the `keystore/` folder, which is git-ignored.

```powershell
# HTTPS keystore (RSA 3072, PKCS12) with a random password
.\scripts\create-keystore.ps1

# AES-256 key for passport encryption
.\scripts\create-encryption-key.ps1
```

`create-keystore.ps1` adds `localhost`, `127.0.0.1`, the computer name and its IP addresses to the certificate, so the API is valid when accessed from other machines on the network. Use `-ExtraSan "dns:host.example"` to add more names. It also exports `keystore/securedb.cer`, which clients can import as trusted.

Do not re-run `create-encryption-key.ps1 -Force` on a database that already has data: existing passports would no longer decrypt.

### 3. Run

```powershell
.\mvnw.cmd spring-boot:run
```

Open **https://localhost:8443**. (Plain http://localhost:8080 redirects there.)

Secrets can also be supplied as environment variables instead of files: `KEYSTORE_PASSWORD`, `TRIPVAULT_KEY`.

### 4. Demo users

On first start the app creates three demo users and sample trips:

| User | Role | Trips |
|---|---|---|
| `alice` | USER | 1 (Kathmandu), 2 (Tokyo) |
| `bob` | USER | 3 (Paris) |
| `admin` | ADMIN | none |

No passwords are stored in the code. Either set one shared demo password before starting:

```powershell
$env:DEMO_PASSWORD = "choose-a-demo-password"
```

or leave it unset and a random password for each user is printed once in the startup log.

## API

All endpoints require login (form login at `/login`, or HTTP Basic). POST and DELETE requests need a CSRF token in the `X-CSRF-TOKEN` header.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/csrf` | Get a CSRF token for API clients |
| GET | `/api/trips` | List my trips (`?destination=Tokyo` to search) |
| GET | `/api/trips/{id}` | One of my trips (404 if it is not mine) |
| POST | `/api/trips` | Create a trip (201 Created) |
| DELETE | `/api/trips/{id}` | Delete one of my trips (204 No Content) |
| GET | `/api/admin/trips` | All trips, ADMIN only (passports still masked) |

Example request body for `POST /api/trips`:

```json
{
  "destination": "Lisbon",
  "departureDate": "2027-03-01",
  "returnDate": "2027-03-05",
  "passportNumber": "pa7654321"
}
```

Response:

```json
{"id":4,"destination":"Lisbon","departureDate":"2027-03-01","returnDate":"2027-03-05","passport":"*****321"}
```

## Tests

```powershell
.\mvnw.cmd test
```

30 automated tests cover passport encryption (round trip, random IV, tamper detection, wrong key), SQL injection payloads, raw database contents, owner isolation, validation, CSRF, login, BCrypt, account lockout, roles, security headers, logout and the HTTPS redirect. Tests run with a test profile (`src/test/resources/application-test.properties`) that uses a throwaway key.

## Project structure

```
src/main/java/com/tripvault/
  config/       HTTP to HTTPS redirect connector, demo data loader
  controller/   REST controllers, CSRF endpoint, safe exception handler
  dto/          Validated input (TripRequest) and masked output (TripView)
  model/        JPA entities: Trip (encrypted passport), AppUser (BCrypt hash)
  repository/   Parameterized, owner-scoped Spring Data repositories
  security/     SecurityConfig, PassportEncryptor, user details, lockout, audit log
  service/      Business logic and ownership checks
src/main/resources/
  application.properties   HTTPS, cookie, error, database and security settings
  schema.sql               Tables with length and CHECK constraints
  templates/               Login page (with phishing notice) and home page
scripts/                   Keystore and encryption key generators
```

## Limitations and next steps

- A phished **correct** password still allows login. The damage is limited (own trips only, masked passports, lockout, audit log), and the main next step is **phishing-resistant MFA with passkeys (FIDO2/WebAuthn)**.
- The certificate is self-signed. Use a certificate from a trusted CA in production.
- H2 runs in memory. In production, use PostgreSQL with a least-privilege database user and keep the AES key in a secrets manager.
- Add per-IP rate limiting so lockout cannot be abused to lock out real users.
