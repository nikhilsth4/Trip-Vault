package com.tripvault;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point of TripVault, a secure trip-booking API served only over HTTPS.
 *
 * @SpringBootApplication = @Configuration + @EnableAutoConfiguration + @ComponentScan:
 * it scans this package (com.tripvault) and sub-packages for components, and auto-configures
 * embedded Tomcat (with the TLS keystore), JPA/Hibernate, the datasource and Spring Security
 * from the dependencies in pom.xml and the settings in application.properties.
 */
@SpringBootApplication
public class TripVaultApplication {

    public static void main(String[] args) {
        SpringApplication.run(TripVaultApplication.class, args);
    }
}
