package com.ludwig.authservice.auth;


import com.ludwig.authservice.auth.dto.LoginRequest;
import com.ludwig.authservice.auth.dto.RegisterRequest;
import com.ludwig.authservice.users.User;
import com.ludwig.authservice.users.UserService;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class AuthService {
    private final UserService userService;
    private final PasswordEncoder encoder;
    private final JwtUtil jwtUtil;

    public AuthService(UserService userService, PasswordEncoder encoder, JwtUtil jwtUtil) {
        this.userService = userService;
        this.encoder = encoder;
        this.jwtUtil = jwtUtil;
    }

    public ResponseCookie login(LoginRequest req) {
        User u = userService.findByEmail(req.getEmail())
                .orElseThrow(() -> new BadCredentialsException("Bad credentials. Invalid email or password."));
        if (!encoder.matches(req.getPassword(), u.getPassword()))
            throw new BadCredentialsException("Bad credentials. Invalid email or password.");

        String token = jwtUtil.generateToken(u);
        return ResponseCookie.from("token", token)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/")
                .maxAge(Duration.ofDays(7))
                .build();
    }

    public ResponseCookie createLogoutCookie() {
        return ResponseCookie.from("token", "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/")
                .maxAge(0)
                .build();
    }

    public void register(RegisterRequest req) {
        if (userService.findByUsername(req.getUsername()).isPresent()) {
            throw new IllegalArgumentException("Username already exists");
        }
        if (userService.findByEmail(req.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already exists");
        }
        User u = req.toUser();
        userService.registerNewUser(u);
    }
}
