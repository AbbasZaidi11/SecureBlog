package org.example.services.impl;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.example.entities.Tag;
import org.example.repositories.TagRepository;
import org.example.services.TagService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class TagServiceImpl implements TagService {

    private final TagRepository tagRepository;

    @Override
    @Transactional(readOnly = true)
    public List<Tag> getTags() {
        return tagRepository.findAllWithPostCount();
    }

    @Override
    @Transactional
    public List<Tag> createTags(Set<String> tagNames) {
        // If you want to normalize names, uncomment next line:
        // tagNames = tagNames.stream().map(s -> s.trim().toLowerCase()).collect(Collectors.toSet());

        List<Tag> existingTags = tagRepository.findByNameIn(tagNames);
        Set<String> existingTagNames = existingTags.stream()
                .map(Tag::getName)
                .collect(Collectors.toSet());

        List<Tag> newTags = tagNames.stream()
                .filter(name -> !existingTagNames.contains(name))
                .map(name -> Tag.builder()
                        .name(name)
                        .posts(new HashSet<>())
                        .build())
                .toList();

        List<Tag> savedTags = newTags.isEmpty() ? new ArrayList<>() : tagRepository.saveAll(newTags);
        savedTags.addAll(existingTags);
        return savedTags;
    }

    @Override
    @Transactional
    public void deleteTag(UUID id) {
        Tag tag = tagRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Tag not found with ID " + id));

        if (!tag.getPosts().isEmpty()) {
            throw new IllegalStateException("Cannot delete tag with posts");
        }
        tagRepository.deleteById(id);
    }

    @Override
    @Transactional(readOnly = true)
    public Tag getTagById(UUID id) {
        return tagRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Tag not found with ID " + id));
    }

    @Override
    public List<Tag> getTagByIds(Set<UUID> ids) {
        List<Tag> foundTags= tagRepository.findAllById(ids);
        if(foundTags.size() != ids.size()){
            throw new EntityNotFoundException("Not all specified tag IDs exist");
        }
        return foundTags;
    }
}
