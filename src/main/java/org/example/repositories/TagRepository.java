package org.example.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;
import org.example.entities.Tag;
import org.springframework.stereotype.Repository;

@Repository
public interface TagRepository extends JpaRepository<Tag, UUID> {

}
