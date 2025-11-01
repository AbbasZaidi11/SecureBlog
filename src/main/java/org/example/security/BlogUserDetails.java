package org.example.security;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.example.entities.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Getter
@RequiredArgsConstructor
// This class adapts YOUR User entity so Spring Security can understand it.
// Spring Security does NOT know your User class. It only understands objects that implement UserDetails.
public class BlogUserDetails implements UserDetails {

    // We store your actual User entity here.
    // This is the user retrieved from the database.
    private final User user;

    // Spring Security asks: "What roles/permissions does this user have?"
    // For now, you are hard-coding ROLE_USER.
    // Later you can pull roles from user.getRoles().
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Each GrantedAuthority represents one security role/permission.
        // "ROLE_USER" is a standard role naming convention in Spring.
        return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    // Spring Security needs the user's password (hashed, from DB)
    @Override
    public String getPassword() {
        return user.getPassword(); // delegate to your entity
    }

    // Spring Security calls this to identify the user (username field).
    // You are telling Spring: "Use email as the username".
    @Override
    public String getUsername() {
        return user.getEmail(); // delegate to your entity
    }

    // These booleans are used for account status checks.
    // Right now, all are true → meaning every user is active and allowed.
    // In production systems, you can add fields in User for banned/expired accounts.

    @Override
    public boolean isAccountNonExpired() {
        return true; // the account is valid and not expired
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // not locked (e.g., after too many failed logins)
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // password has not expired
    }

    @Override
    public boolean isEnabled() {
        return true; // account is active
    }

    // Custom helper method — not required by Spring.
    // Useful when you need the actual user ID later (e.g., inside controllers).
    public UUID getId() {
        return user.getId();
    }
}
