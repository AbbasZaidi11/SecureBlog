package org.example.services.impl;

import lombok.RequiredArgsConstructor;
import org.example.entities.Category;
import org.example.repositories.CategoryRepository;
import org.example.services.CategoryService;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CategoryServiceImpl implements CategoryService {

    private final CategoryRepository categoryRepository;

    @Override
    public List<Category> listCategories() {
        // use the custom query that fetches posts to avoid LazyInitializationException and N+1
        return categoryRepository.findAllWithPostCount();
    }
}
