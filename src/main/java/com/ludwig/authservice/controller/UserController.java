package com.ludwig.authservice.controller;

import com.ludwig.authservice.model.User;
import com.ludwig.authservice.service.UserService;
import com.ludwig.authservice.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody User user){
        if(userService.findByUsername(user.getUsername()).isPresent())
            return new ResponseEntity<>("Username already exists", HttpStatus.BAD_REQUEST);

        if(userService.findByEmail(user.getEmail()).isPresent())
            return new ResponseEntity<>("Email already exits", HttpStatus.BAD_REQUEST);

        userService.registerNewUser(user);
        return new ResponseEntity<>("User registered successfully", HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<String> loginUser(@RequestBody User user){
        Optional<User> foundUser =  userService.findByEmail(user.getEmail());

        if(foundUser.isEmpty())
            return new ResponseEntity<>("Email not found", HttpStatus.NOT_FOUND);

        if(!passwordEncoder.matches(user.getPassword(), foundUser.get().getPassword()))
            return new ResponseEntity<>("Invalid password", HttpStatus.UNAUTHORIZED);

        String token = jwtUtil.generateToken(foundUser.get().getId());
        return new ResponseEntity<>(token, HttpStatus.OK);
    }
}
