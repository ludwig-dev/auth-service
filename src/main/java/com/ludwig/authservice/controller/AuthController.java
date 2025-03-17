package com.ludwig.authservice.controller;

import com.ludwig.authservice.model.User;
import com.ludwig.authservice.service.UserService;
import com.ludwig.authservice.util.EmailValidator;
import com.ludwig.authservice.util.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Optional;


@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthController(UserService userService, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody User user) {

        if (!EmailValidator.isValid(user.getEmail())) {
            return new ResponseEntity<>("Invalid email format", HttpStatus.BAD_REQUEST);
        }

        if (userService.findByUsername(user.getUsername()).isPresent())
            return new ResponseEntity<>("Username already exists", HttpStatus.BAD_REQUEST);

        if (userService.findByEmail(user.getEmail()).isPresent())
            return new ResponseEntity<>("Email already exits", HttpStatus.BAD_REQUEST);

        userService.registerNewUser(user);
        return new ResponseEntity<>("User registered successfully", HttpStatus.CREATED);
    }


    @PostMapping("/login")
    public ResponseEntity<Void> loginUser(@RequestBody User user, HttpServletResponse response) {
        Optional<User> foundUser = userService.findByEmail(user.getEmail());

        if (!EmailValidator.isValid(user.getEmail())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        if (foundUser.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        if (!passwordEncoder.matches(user.getPassword(), foundUser.get().getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // Generate JWT Token
        String token = jwtUtil.generateToken(foundUser.get().getId(), foundUser.get().getRole());

        // Create HTTP-Only Secure Cookie
        ResponseCookie jwtCookie = ResponseCookie.from("token", token)
                .httpOnly(true)       // Prevents XSS attacks
                .secure(true)         // end only over HTTPS
                .sameSite("Strict")   // Prevents CSRF attacks
                .path("/")            // Available for the whole application
                .maxAge(Duration.ofDays(7)) // ⏳ Expires after 7 days
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, jwtCookie.toString());

        return ResponseEntity.ok().build();
    }
}
