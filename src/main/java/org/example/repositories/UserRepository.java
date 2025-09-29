package org.example.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.example.entities.User;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

}
