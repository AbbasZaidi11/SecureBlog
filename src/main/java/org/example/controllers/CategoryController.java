package org.example.controllers;

import lombok.RequiredArgsConstructor;
import org.example.dtos.CategoryDto;
import org.example.services.CategoryService;
import org.example.mappers.CategoryMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping(path = "/api/v1/categories")
@RequiredArgsConstructor
public class CategoryController {

    private final CategoryService categoryService;
    private final CategoryMapper categoryMapper;

    @GetMapping
    public ResponseEntity<List<CategoryDto>> listCategories() {
        List<CategoryDto> categories = categoryService.listCategories()
                .stream()
                .map(categoryMapper::toDto)   // no extra space
                .toList();                    // Java 16+; otherwise use Collectors.toList()
        return ResponseEntity.ok(categories);
    }
}
