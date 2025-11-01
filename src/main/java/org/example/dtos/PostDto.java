package org.example.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.entities.PostStatus;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder

public class PostDto {
    private UUID id;
    private String title;
    private String content;
    private AuthorDto author;
    // TODO: Author
    private CategoryDto category;
    private Set<TagDto> tags;
    private Integer readingTime;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private PostStatus status;
}
