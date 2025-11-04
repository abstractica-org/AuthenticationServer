package com.auth.server.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Home controller for the root endpoint.
 * Serves the landing page with API documentation.
 */
@Controller
public class HomeController {

    /**
     * Serve the home/landing page
     * Forwards to the static index.html file
     *
     * @return Forward to static resource
     */
    @GetMapping("/")
    public String home() {
        return "forward:/index.html";
    }
}
