package com.ludwig.authservice.filter;

import com.ludwig.authservice.model.User;
import com.ludwig.authservice.service.UserService;
import com.ludwig.authservice.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class JwtRequestFilter extends OncePerRequestFilter implements ApplicationContextAware {

    private final JwtUtil jwtUtil;
    private static ApplicationContext applicationContext;

    public JwtRequestFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void setApplicationContext(ApplicationContext context) {
        applicationContext = context;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");

        Long userId = null;
        String jwt = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            userId = jwtUtil.extractUserId(jwt);
        }

        // If userId is valid and no authentication is currently set
        if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Dynamically fetch UserService at runtime to prevent circular dependency
            UserService userService = applicationContext.getBean(UserService.class);
            User user = userService.findById(userId).orElse(null);

            if (user != null && jwtUtil.validateToken(jwt, user.getId())) {
                UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                        user.getUsername(),
                        user.getPassword(),
                        List.of(() -> "ROLE_" + user.getRole())  // Assign roles
                );

                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        chain.doFilter(request, response);
    }
}
