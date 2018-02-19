package com.exp.controller;

import org.springframework.web.bind.annotation.RestController;

/**
 * Created by rohith on 17/2/18.
 */

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@RestController
@RequestMapping("/secure")
public class UserController {

    @GetMapping("/user")
    public @ResponseBody Map<String, String> getUser() {
        return getSuccessResponse();
    }

    @GetMapping("/admin")
    public @ResponseBody Map<String, String> getAdmin() {
        return getSuccessResponse();
    }

    @PreAuthorize("hasRole('PARTICIPANT')")
    @GetMapping("/participant")
    public @ResponseBody Map<String, String> getParticipant() {
        return getSuccessResponse();
    }


    private Set<String> getRoles(Authentication authentication) {
        return authentication.getAuthorities().stream().map(r -> r.getAuthority()).collect(Collectors.toSet());
    }

    private Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private Map<String, String> getSuccessResponse() {
        Authentication authentication = getAuthentication();
        Set<String> roles = getRoles(authentication);
        Map<String, String> response = new HashMap<>();
        response.put("username", authentication.getName());
        response.put("role", roles.toString());
        response.put("message", "success");
        return response;
    }
}

