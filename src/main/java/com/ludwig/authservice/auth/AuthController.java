package com.ludwig.authservice.auth;

import com.ludwig.authservice.auth.dto.LoginRequest;
import com.ludwig.authservice.auth.dto.RegisterRequest;
import com.ludwig.authservice.users.User;
import com.ludwig.authservice.users.UserService;
import com.ludwig.authservice.util.EmailValidator;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(
            @Valid @RequestBody RegisterRequest req) {

        authService.register(req);
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body("User registered successfully");
    }


    @PostMapping("/login")
    public ResponseEntity<Void> login(@Valid @RequestBody LoginRequest req,
                                      HttpServletResponse resp) {
        ResponseCookie cookie = authService.login(req);
        resp.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        ResponseCookie cookie = authService.createLogoutCookie();
        response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        return ResponseEntity.ok().build();
    }
}
