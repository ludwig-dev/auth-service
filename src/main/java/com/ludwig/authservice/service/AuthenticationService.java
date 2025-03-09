package com.ludwig.authservice.service;

import com.ludwig.authservice.model.User;
import com.ludwig.authservice.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    public Long getAuthenticatedUserId(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return null;
        }

        String token = authorizationHeader.substring(7);
        String username = jwtUtil.extractUsername(token);

        // Now fetch the user just once
        User user = userDetailsService.getUserByUsername(username);

        // Return the user ID
        return user != null ? user.getId() : null;
    }

}
