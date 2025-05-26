package com.ludwig.authservice.auth.dto;

import com.ludwig.authservice.users.User;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {
    @NotBlank
    @Size(min = 3, max = 50)
    private String username;

    @NotBlank
    @Email
    private String email;

    @NotBlank
    @Size(min = 3)
    private String password;

    public User toUser() {
        User u = new User();
        u.setUsername(username);
        u.setEmail(email);
        u.setPassword(password);
        return u;
    }
}
