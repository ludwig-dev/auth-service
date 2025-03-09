package com.ludwig.authservice.controller;

import com.ludwig.authservice.model.User;
import com.ludwig.authservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody User user){
        if(userService.findByUsername(user.getUsername()).isPresent()){
            return new ResponseEntity<>("Username already exists", HttpStatus.BAD_REQUEST);
        }
        userService.registerNewUser(user);
        return new ResponseEntity<>("User registered successfully", HttpStatus.CREATED);
    }
}
