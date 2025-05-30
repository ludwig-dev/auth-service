package com.ludwig.authservice.users;

import com.ludwig.authservice.exceptions.BadRequestException;
import com.ludwig.authservice.exceptions.ResourceNotFoundException;
import com.ludwig.authservice.users.dto.UserDTO;
import com.ludwig.authservice.users.dto.UserUpdateDTO;
import com.ludwig.authservice.util.EmailValidator;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsernameIgnoreCase(username.toLowerCase());
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmailIgnoreCase(email.toLowerCase());
    }

    public UserDTO updateUser(Long userId, UserUpdateDTO upd) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (upd.getUsername() != null) {
            String name = upd.getUsername().trim().toLowerCase();
            if (name.isEmpty())
                throw new BadRequestException("Username cannot be empty");
            if (userRepository.findByUsernameIgnoreCase(name).isPresent())
                throw new BadRequestException("Username already taken");
            user.setUsername(name);
        }

        if (upd.getEmail() != null) {
            String email = upd.getEmail().trim().toLowerCase();
            if (email.isEmpty())
                throw new BadRequestException("Email cannot be empty");
            if (!EmailValidator.isValid(email))
                throw new BadRequestException("Invalid email format");
            if (userRepository.findByEmailIgnoreCase(email).isPresent())
                throw new BadRequestException("Email already taken");
            user.setEmail(email);
        }
        User saved = userRepository.save(user);
        return convertToDTO(saved);
    }

    public void registerNewUser(User user) {
        user.setRole("USER");
        user.setEmail(user.getEmail().toLowerCase());
        user.setUsername(user.getUsername().toLowerCase());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
    }

    public UserDTO getUserInfo(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() ->
                        new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        return convertToDTO(user);
    }

    public List<UserDTO> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    public UserDTO updateUserRole(Long userId, String role) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        user.setRole(role);
        return convertToDTO(userRepository.save(user));
    }

    public void deleteUserById(Long userId) {
        if (!userRepository.existsById(userId))
            throw new ResourceNotFoundException("User not found");
        userRepository.deleteById(userId);
    }

    public List<UserDTO> searchByUsername(String username) {
        List<User> userList = userRepository.findByUsernameContainingIgnoreCase(username);
        return userList.stream()
                .map(this::convertToDTO)
                .collect(Collectors.toList());
    }

    private UserDTO convertToDTO(User user) {
        return new UserDTO(user.getId(), user.getUsername(), user.getEmail(), user.getRole());
    }

}
