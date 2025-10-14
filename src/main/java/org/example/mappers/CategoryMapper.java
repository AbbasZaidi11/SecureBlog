package org.example.mappers;

import org.example.dtos.CategoryDto;
import org.example.entities.Category;
import org.example.entities.Post;
import org.example.entities.PostStatus;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;
import org.mapstruct.ReportingPolicy;

import java.util.List;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface CategoryMapper {

    // use the same name in qualifiedByName and @Named below:
    @Mapping(target = "postCount", source = "posts", qualifiedByName = "calculatePostCount")
    CategoryDto toDto(Category category);

    @Named("calculatePostCount")
    default long calculatePostCount(List<Post> posts){
        if (posts == null) {
            return 0L;
        }
        return posts.stream()
                .filter(post -> PostStatus.PUBLISHED.equals(post.getStatus()))
                .count();
    }
}
