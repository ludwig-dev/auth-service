package com.ludwig.authservice.service;

import com.ludwig.authservice.model.User;
import com.ludwig.authservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Optional<User> findByUsername(String username){
        return userRepository.findByUsername(username);
    }

    public Optional<User> findByEmail(String email){
        return userRepository.findByEmail(email);
    }

    public Optional<User> findById(Long userId){
        return userRepository.findById(userId);
    }

    public User registerNewUser(User user) {
        user.setRole("USER");
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }
}
