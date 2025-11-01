package org.example.security;

import lombok.Builder;
import org.example.entities.User;
import org.example.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// This class tells Spring Security HOW to load a user from the database.
// Spring Security doesn't know how to fetch your user; so you implement UserDetailsService.
// When a login happens, Spring calls loadUserByUsername() to find the user.
public class BlogUserDetailsService implements UserDetailsService {

    // We inject our UserRepository so we can query database for a user.
    private final UserRepository userRepository;

    // This method is automatically called by Spring Security during authentication.
    // The "email" parameter comes from login input (the username field).
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        // Look up the user from DB by email.
        // If no user found, throw exception (Spring expects this form).
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        // Convert your User entity into a Spring Security-compatible object (BlogUserDetails)
        // This wraps the user and gives Spring the required methods like getPassword(), getAuthorities(), etc.
        return new BlogUserDetails(user);
    }

    // Constructor injection — Spring passes UserRepository here when creating this bean.
    public BlogUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
}
