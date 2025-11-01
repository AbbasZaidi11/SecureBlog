package org.example.services;

import org.example.entities.User;

import java.util.UUID;

public interface UserService {
    User getUserById(UUID id);
}
