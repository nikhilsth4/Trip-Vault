package com.tripvault.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** With the production setting require-https=true, any plain-HTTP request is redirected to HTTPS. */
@SpringBootTest(properties = "tripvault.security.require-https=true")
@AutoConfigureMockMvc
@ActiveProfiles("test")
class HttpsRedirectTest {

    @Autowired MockMvc mvc;

    @Test
    void plainHttpIsRedirectedToHttps() throws Exception {
        mvc.perform(get("/api/trips"))                      // MockMvc default: http, not secure
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("https://**"));
    }
}
