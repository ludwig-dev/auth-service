package com.ludwig.authservice.controller;

import com.ludwig.authservice.model.User;
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
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public UserController(UserService userService, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody User user) {
        if (userService.findByUsername(user.getUsername()).isPresent())
            return new ResponseEntity<>("Username already exists", HttpStatus.BAD_REQUEST);

        if (userService.findByEmail(user.getEmail()).isPresent())
            return new ResponseEntity<>("Email already exits", HttpStatus.BAD_REQUEST);

        if (!EmailValidator.isValid(user.getEmail())) {
            return new ResponseEntity<>("Invalid email format", HttpStatus.BAD_REQUEST);
        }

        userService.registerNewUser(user);
        return new ResponseEntity<>("User registered successfully", HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<String> loginUser(@RequestBody User user) {
        Optional<User> foundUser = userService.findByEmail(user.getEmail());

        if (foundUser.isEmpty())
            return new ResponseEntity<>("Email not found", HttpStatus.NOT_FOUND);

        if (!passwordEncoder.matches(user.getPassword(), foundUser.get().getPassword()))
            return new ResponseEntity<>("Invalid password", HttpStatus.UNAUTHORIZED);

        String token = jwtUtil.generateToken(foundUser.get().getId());
        return new ResponseEntity<>(token, HttpStatus.OK);
    }

    @PutMapping("/update/username")
    public ResponseEntity<String> updateUsername(@RequestHeader("Authorization") String authHeader,
                                                 @RequestBody Map<String, String> requestBody) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new ResponseEntity<>("Invalid authorization header", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);
        Long userId = jwtUtil.extractUserId(token);  // Extract user ID from token
        String newUsername = requestBody.get("newUsername");

        if (newUsername == null || newUsername.trim().isEmpty())
            return new ResponseEntity<>("Username can not be empty", HttpStatus.BAD_REQUEST);

        if (userService.findByUsername(newUsername).isPresent())
            return new ResponseEntity<>("Username already taken", HttpStatus.BAD_REQUEST);

        boolean isUpdated = userService.updateUsername(userId, newUsername);
        if (!isUpdated)
            return new ResponseEntity<>("Failed to update username", HttpStatus.INTERNAL_SERVER_ERROR);

        return new ResponseEntity<>("Username updated successfully", HttpStatus.OK);
    }

    @PutMapping("/update/email")
    public ResponseEntity<String> updateEmail(@RequestHeader("Authorization") String authHeader,
                                              @RequestBody Map<String, String> requestBody) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return new ResponseEntity<>("Invalid authorization header", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);
        Long userId = jwtUtil.extractUserId(token);
        String newEmail = requestBody.get("newEmail");

        if (newEmail == null || newEmail.trim().isEmpty())
            return new ResponseEntity<>("Email is empty", HttpStatus.BAD_REQUEST);

        if (!EmailValidator.isValid(newEmail))
            return new ResponseEntity<>("Invalid email format", HttpStatus.BAD_REQUEST);

        if (userService.findByEmail(newEmail).isPresent())
            return new ResponseEntity<>("Email is taken", HttpStatus.BAD_REQUEST);

        boolean isUpdated = userService.updateEmail(userId, newEmail);
        if (!isUpdated)
            return new ResponseEntity<>("Failed to update username", HttpStatus.INTERNAL_SERVER_ERROR);

        return new ResponseEntity<>("Email updated successfully", HttpStatus.OK);
    }
}

