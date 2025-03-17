package com.ludwig.authservice.filter;

import com.ludwig.authservice.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.http.Cookie;
import org.springframework.security.core.userdetails.User;


import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Arrays;

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

        String jwt = getJwtFromCookies(request); // ✅ Extract token from cookies

        if (jwt != null && jwtUtil.validateToken(jwt)) { // ✅ Validate token before extracting data
            Long userId = jwtUtil.extractUserId(jwt);
            String role = jwtUtil.extractRole(jwt);

            if (SecurityContextHolder.getContext().getAuthentication() == null) { // ✅ Prevent duplicate authentication
                List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));

                User userDetails = new User(userId.toString(), "", authorities);

                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        chain.doFilter(request, response);
    }

    // Helper method to extract JWT from cookies
    private String getJwtFromCookies(HttpServletRequest request) {
        if (request.getCookies() != null) {
            Optional<Cookie> jwtCookie = Arrays.stream(request.getCookies())
                    .filter(cookie -> "token".equals(cookie.getName()))
                    .findFirst();

            return jwtCookie.map(Cookie::getValue).orElse(null);
        }
        return null;
    }

}
