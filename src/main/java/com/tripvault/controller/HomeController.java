package com.tripvault.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/** Serves the HTML pages: the custom login page and the home page after login. */
@Controller
public class HomeController {

    /** Public login page (see templates/login.html). Spring Security handles the POST /login. */
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    /** Home page; only reachable after login. */
    @GetMapping("/")
    public String home(Authentication auth, Model model) {
        model.addAttribute("username", auth.getName());
        return "home";
    }
}
