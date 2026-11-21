package com.tripvault.config;

import org.apache.catalina.connector.Connector;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Opens a second, plain-HTTP port (8080) whose only job is to send users to HTTPS.
 *
 * Someone typing "http://server:8080" gets a redirect to "https://server:8443" (done by
 * http.redirectToHttps() in SecurityConfig). Without this connector, that request would just
 * fail. No page or data is ever served over plain HTTP.
 */
@Configuration
@ConditionalOnProperty(name = "server.ssl.enabled", havingValue = "true")
public class HttpToHttpsRedirectConfig {

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> httpRedirectConnector(
            @Value("${tripvault.http.port:8080}") int httpPort,
            @Value("${server.port}") int httpsPort) {
        return factory -> {
            Connector connector = new Connector();
            connector.setScheme("http");
            connector.setSecure(false);
            connector.setPort(httpPort);
            connector.setRedirectPort(httpsPort);
            factory.addAdditionalConnectors(connector);
        };
    }
}
