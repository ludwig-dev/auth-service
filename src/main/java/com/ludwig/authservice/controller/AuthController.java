package com.ludwig.authservice.controller;

import com.ludwig.authservice.dto.UserDTO;
import com.ludwig.authservice.model.User;
import com.ludwig.authservice.service.TokenBlacklistService;
import com.ludwig.authservice.service.UserService;
import com.ludwig.authservice.util.EmailValidator;
import com.ludwig.authservice.util.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;


@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final TokenBlacklistService tokenBlacklistService;

    public AuthController(UserService userService, PasswordEncoder passwordEncoder, JwtUtil jwtUtil, TokenBlacklistService tokenBlacklistService) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.tokenBlacklistService = tokenBlacklistService;
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
    public ResponseEntity<Map<String, String>> loginUser(@RequestBody User user) {
        Optional<User> foundUser = userService.findByEmail(user.getEmail());

        if (!EmailValidator.isValid(user.getEmail())) {
            return new ResponseEntity<>(Map.of("error", "Invalid email"), HttpStatus.BAD_REQUEST);
        }

        if (foundUser.isEmpty())
            return new ResponseEntity<>(Map.of("error", "Email not found"), HttpStatus.NOT_FOUND);

        if (!passwordEncoder.matches(user.getPassword(), foundUser.get().getPassword()))
            return new ResponseEntity<>(Map.of("error", "Invalid password"), HttpStatus.UNAUTHORIZED);

        String token = jwtUtil.generateToken(foundUser.get().getId(), foundUser.get().getRole());
        return ResponseEntity.ok(Map.of("token", token));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logoutUser(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new ResponseEntity<>("Invalid authorization header", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);
        tokenBlacklistService.addToBlacklist(token);

        return new ResponseEntity<>("Logged out successfully", HttpStatus.OK);
    }
}
