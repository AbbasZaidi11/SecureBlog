package org.example.controllers;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.dtos.CategoryDto;
import org.example.dtos.CreateCategoryRequest;
import org.example.entities.Category;
import org.example.services.CategoryService;
import org.example.mappers.CategoryMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * CATEGORY CONTROLLER
 * ===================
 * PURPOSE: Handles all HTTP requests related to blog categories.
 *          This is a CRUD controller (Create, Read, Update, Delete).
 *
 * WHAT ARE CATEGORIES?
 *   - Blog posts are organized into categories (e.g., Technology, Travel, Food)
 *   - Categories help users find related content
 *   - This controller lets you manage these categories via REST API
 *
 * BASE URL: /api/v1/categories
 * =============================
 * All endpoints in this controller start with this path.
 *
 * AVAILABLE ENDPOINTS:
 *   - GET    /api/v1/categories          → List all categories
 *   - POST   /api/v1/categories          → Create new category
 *   - DELETE /api/v1/categories/{id}     → Delete category by ID
 *
 * ANNOTATIONS EXPLAINED:
 *
 * @RestController:
 *   - Marks this as a REST API controller
 *   - Automatically converts Java objects ↔ JSON
 *   - All responses are JSON (not HTML pages)
 *
 * @RequestMapping(path = "/api/v1/categories"):
 *   - Base path for all methods in this controller
 *   - Using versioning (/v1/) is good practice for API evolution
 *   - If you later make breaking changes, you can create /api/v2/categories
 *
 * @RequiredArgsConstructor (Lombok):
 *   - Auto-generates constructor for 'final' fields
 *   - Spring uses this to inject dependencies
 *   - Saves you from writing boilerplate constructor code
 */
@RestController
@RequestMapping(path = "/api/v1/categories")
@RequiredArgsConstructor
public class CategoryController {

    /**
     * DEPENDENCY: CATEGORY SERVICE
     * ============================
     * Contains business logic for category operations.
     *
     * RESPONSIBILITY SEPARATION:
     *   - Controller: Handles HTTP requests/responses
     *   - Service: Contains business logic and validation
     *   - Repository: Talks to the database
     *
     * WHY SEPARATE?
     *   - Keeps code organized and testable
     *   - Service logic can be reused by multiple controllers
     *   - Easier to mock in unit tests
     */
    private final CategoryService categoryService;

    /**
     * DEPENDENCY: CATEGORY MAPPER
     * ===========================
     * Converts between different representations of Category data.
     *
     * WHAT IS A MAPPER?
     *   - Transforms Entity ↔ DTO (Data Transfer Object)
     *   - Entity: Database representation (JPA entity)
     *   - DTO: API representation (what clients see)
     *
     * WHY USE DTOs?
     *   - Hide internal database structure from API users
     *   - Control exactly what data is exposed
     *   - Can have different DTOs for different use cases
     *   - Prevent over-fetching (exposing sensitive fields)
     *
     * EXAMPLE:
     *   Category Entity (database):
     *     { id, name, slug, createdAt, updatedAt, posts, ... }
     *
     *   CategoryDto (API):
     *     { id, name, slug }  ← Only expose what's needed
     */
    private final CategoryMapper categoryMapper;

    /**
     * LIST ALL CATEGORIES ENDPOINT
     * ============================
     * URL: GET /api/v1/categories
     *
     * PURPOSE: Retrieves all categories from the database
     *
     * SECURITY:
     *   - This endpoint is PUBLIC (see SecurityConfig)
     *   - No authentication required
     *   - Anyone can view categories
     *
     * @GetMapping:
     *   - Maps HTTP GET requests to this method
     *   - GET is for reading data (no side effects)
     *   - Idempotent: calling multiple times has same result
     *
     * ResponseEntity<List<CategoryDto>>:
     *   - Returns HTTP response containing a list of categories
     *   - <List<CategoryDto>> is the response body type
     *   - Will be converted to JSON array automatically
     *
     * ==========================================
     * EXECUTION FLOW:
     * ==========================================
     *
     * CLIENT REQUEST:
     * ---------------
     * GET /api/v1/categories
     * Accept: application/json
     *
     *
     * SERVER PROCESSING:
     * ------------------
     * 1. Spring routes request to this method
     * 2. Method executes (see steps below)
     * 3. Returns ResponseEntity with list
     * 4. Spring converts List<CategoryDto> → JSON array
     * 5. Sends response to client
     *
     *
     * EXPECTED RESPONSE:
     * ------------------
     * HTTP/1.1 200 OK
     * Content-Type: application/json
     *
     * [
     *   { "id": "123e4567-e89b-12d3-a456-426614174000", "name": "Technology", "slug": "technology" },
     *   { "id": "223e4567-e89b-12d3-a456-426614174001", "name": "Travel", "slug": "travel" },
     *   { "id": "323e4567-e89b-12d3-a456-426614174002", "name": "Food", "slug": "food" }
     * ]
     */
    @GetMapping
    public ResponseEntity<List<CategoryDto>> listCategories() {

        // STEP 1: Fetch all categories from database
        // ==========================================
        // categoryService.listCategories() calls the repository
        // Returns: List<Category> (entity objects from database)
        //
        // Example result:
        //   [ Category(id=UUID, name="Tech", ...), Category(id=UUID, name="Travel", ...) ]
        List<CategoryDto> categories = categoryService.listCategories()

                // STEP 2: Convert to Stream for processing
                // =========================================
                // .stream() converts List → Stream
                // Streams allow functional-style operations (map, filter, etc.)
                // Think of it like a pipeline of data transformations
                .stream()

                // STEP 3: Transform each Category entity to CategoryDto
                // =====================================================
                // .map() applies a function to each element
                // categoryMapper::toDto is a method reference
                //
                // Equivalent to: .map(category -> categoryMapper.toDto(category))
                //
                // For each Category entity:
                //   Category(id, name, slug, posts, createdAt, ...)
                //   → CategoryDto(id, name, slug)
                //
                // Why transform?
                //   - DTOs are lighter (no unnecessary fields)
                //   - Hides database structure from API consumers
                //   - Prevents accidental exposure of sensitive data
                .map(categoryMapper::toDto)

                // STEP 4: Collect back into a List
                // =================================
                // .toList() creates an immutable List from the Stream
                // This is Java 16+ feature
                //
                // Before Java 16, you would use:
                //   .collect(Collectors.toList())
                //
                // Result: List<CategoryDto> ready to send to client
                .toList();

        // STEP 5: Wrap in ResponseEntity and return
        // ==========================================
        // ResponseEntity.ok() creates response with:
        //   - HTTP Status: 200 OK
        //   - Body: List<CategoryDto> (converted to JSON automatically)
        //   - Headers: Content-Type: application/json (automatic)
        //
        // Spring's Jackson library converts:
        //   List<CategoryDto> → JSON array
        return ResponseEntity.ok(categories);
    }

    /**
     * CREATE CATEGORY ENDPOINT
     * ========================
     * URL: POST /api/v1/categories
     *
     * PURPOSE: Creates a new category in the database
     *
     * SECURITY:
     *   - This endpoint is PROTECTED (see SecurityConfig)
     *   - Requires authentication (valid JWT token)
     *   - Only authenticated users can create categories
     *
     * @PostMapping:
     *   - Maps HTTP POST requests to this method
     *   - POST is for creating new resources
     *   - Not idempotent: calling twice creates two categories
     *
     * @Valid:
     *   - Triggers validation on CreateCategoryRequest
     *   - Checks annotations like @NotBlank, @Size, @Pattern
     *   - If validation fails → returns 400 Bad Request automatically
     *   - Method is never called if validation fails
     *
     * @RequestBody:
     *   - Tells Spring to convert JSON from request body → Java object
     *   - Content-Type must be application/json
     *   - Jackson deserializes JSON → CreateCategoryRequest
     *
     * CreateCategoryRequest:
     *   - DTO for creating a category
     *   - Contains only fields needed for creation (e.g., name, slug)
     *   - Doesn't include id (generated by database)
     *   - Doesn't include timestamps (set automatically)
     *
     * ==========================================
     * EXECUTION FLOW:
     * ==========================================
     *
     * CLIENT REQUEST:
     * ---------------
     * POST /api/v1/categories
     * Authorization: Bearer eyJhbGciOiJI...
     * Content-Type: application/json
     *
     * {
     *   "name": "Photography",
     *   "slug": "photography"
     * }
     *
     *
     * VALIDATION PHASE (Before method executes):
     * -------------------------------------------
     * - Spring validates CreateCategoryRequest
     * - Checks: @NotBlank on name, @Pattern on slug, etc.
     * - If invalid → Method never called, returns 400 Bad Request
     * - If valid → Method executes
     *
     *
     * SERVER PROCESSING:
     * ------------------
     * 1. JwtAuthenticationFilter validates token
     * 2. Spring validates request body (@Valid)
     * 3. Routes to this method
     * 4. Method executes (see steps below)
     * 5. Returns ResponseEntity with created category
     * 6. Spring converts CategoryDto → JSON
     * 7. Sends response with 201 Created status
     *
     *
     * EXPECTED RESPONSE:
     * ------------------
     * HTTP/1.1 201 Created
     * Content-Type: application/json
     * Location: /api/v1/categories/423e4567-e89b-12d3-a456-426614174003
     *
     * {
     *   "id": "423e4567-e89b-12d3-a456-426614174003",
     *   "name": "Photography",
     *   "slug": "photography"
     * }
     */
    @PostMapping
    public ResponseEntity<CategoryDto> createCategory(
            @Valid @RequestBody CreateCategoryRequest createCategoryRequest){

        // STEP 1: Convert DTO to Entity
        // ==============================
        // CreateCategoryRequest (DTO) → Category (Entity)
        //
        // Why convert?
        //   - Service layer works with entities, not DTOs
        //   - Entities have JPA annotations for database mapping
        //   - Keeps API contracts separate from database structure
        //
        // Mapper sets:
        //   - name, slug from the request
        //   - id will be null (generated by database)
        //   - timestamps will be null (set by @PrePersist)
        Category categoryToCreate = categoryMapper.toEntity(createCategoryRequest);

        // STEP 2: Save to database
        // ========================
        // categoryService.createCategory() does:
        //   a) Additional validation (business rules)
        //   b) Checks for duplicates (e.g., slug already exists)
        //   c) Calls categoryRepository.save()
        //   d) Database generates ID and sets timestamps
        //   e) Returns the saved entity with generated fields
        //
        // savedCategory now has:
        //   - Generated UUID in 'id' field
        //   - Timestamps in 'createdAt', 'updatedAt'
        //   - All the data from categoryToCreate
        Category savedCategory = categoryService.createCategory(categoryToCreate);

        // STEP 3: Convert entity back to DTO and return
        // ==============================================
        // Category (Entity) → CategoryDto (DTO)
        //
        // Why convert again?
        //   - API should return DTOs, not entities
        //   - DTOs expose only necessary fields
        //   - Prevents lazy-loading issues (N+1 queries)
        //
        // ResponseEntity constructor parameters:
        //   1. Body: categoryMapper.toDto(savedCategory)
        //   2. Status: HttpStatus.CREATED (201)
        //
        // HTTP 201 CREATED:
        //   - Indicates successful resource creation
        //   - RESTful convention for POST requests
        //   - Better than 200 OK (which is for generic success)
        //
        // COULD ALSO ADD Location header:
        //   .header("Location", "/api/v1/categories/" + savedCategory.getId())
        //   - Tells client where to find the created resource
        return new ResponseEntity<>(
                categoryMapper.toDto(savedCategory),
                HttpStatus.CREATED
        );
    }

    /**
     * DELETE CATEGORY ENDPOINT
     * ========================
     * URL: DELETE /api/v1/categories/{id}
     *
     * PURPOSE: Deletes a category from the database
     *
     * SECURITY:
     *   - This endpoint is PROTECTED (see SecurityConfig)
     *   - Requires authentication (valid JWT token)
     *   - Only authenticated users can delete categories
     *
     * @DeleteMapping(path = "/{id}"):
     *   - Maps HTTP DELETE requests to this method
     *   - {id} is a path variable (placeholder in URL)
     *   - Example URLs:
     *     DELETE /api/v1/categories/123e4567-e89b-12d3-a456-426614174000
     *     DELETE /api/v1/categories/223e4567-e89b-12d3-a456-426614174001
     *
     * @PathVariable:
     *   - Extracts {id} from URL path
     *   - Automatically converts String → UUID
     *   - If conversion fails → returns 400 Bad Request
     *
     * UUID:
     *   - Universally Unique Identifier
     *   - 128-bit number, typically displayed as 36 characters
     *   - Example: 123e4567-e89b-12d3-a456-426614174000
     *   - Better than auto-increment integers for distributed systems
     *   - Harder to guess (more secure)
     *
     * ResponseEntity<Void>:
     *   - <Void> means no response body
     *   - Just HTTP status code, no content
     *   - Appropriate for DELETE operations
     *
     * ==========================================
     * EXECUTION FLOW:
     * ==========================================
     *
     * CLIENT REQUEST:
     * ---------------
     * DELETE /api/v1/categories/123e4567-e89b-12d3-a456-426614174000
     * Authorization: Bearer eyJhbGciOiJI...
     *
     *
     * SERVER PROCESSING:
     * ------------------
     * 1. JwtAuthenticationFilter validates token
     * 2. Spring extracts UUID from path
     * 3. Routes to this method
     * 4. Method executes (see steps below)
     * 5. Returns ResponseEntity with no body
     * 6. Sends 204 No Content response
     *
     *
     * EXPECTED RESPONSE (Success):
     * ----------------------------
     * HTTP/1.1 204 No Content
     *
     * (empty body)
     *
     *
     * POSSIBLE ERROR RESPONSES:
     * -------------------------
     * Category not found:
     *   HTTP/1.1 404 Not Found
     *   { "error": "Category not found" }
     *
     * Category has posts (can't delete):
     *   HTTP/1.1 409 Conflict
     *   { "error": "Cannot delete category with existing posts" }
     *
     * Invalid UUID format:
     *   HTTP/1.1 400 Bad Request
     *   { "error": "Invalid UUID format" }
     */
    @DeleteMapping(path = "/{id}")
    public ResponseEntity<Void> deleteCategory(@PathVariable UUID id){

        // STEP 1: Delete the category
        // ===========================
        // categoryService.deleteCategory() does:
        //   a) Checks if category exists
        //   b) Checks if category can be deleted (business rules)
        //      - Example: Can't delete if it has posts
        //   c) Calls categoryRepository.deleteById(id)
        //   d) If not found → throws exception (handled globally)
        //
        // WHAT HAPPENS TO RELATED DATA?
        //   - Depends on your database relationships:
        //   - CASCADE DELETE: Deletes all posts in this category (dangerous!)
        //   - SET NULL: Sets category_id to null in posts (posts remain)
        //   - RESTRICT: Prevents deletion if category has posts (safest)
        //
        // EXCEPTION HANDLING:
        //   - If category not found → EntityNotFoundException
        //   - If has related posts → BusinessException
        //   - Global @ControllerAdvice catches these and returns proper HTTP status
        categoryService.deleteCategory(id);

        // STEP 2: Return success response
        // ================================
        // HTTP 204 NO CONTENT:
        //   - Indicates successful deletion
        //   - No response body needed (resource is gone)
        //   - RESTful convention for DELETE operations
        //
        // new ResponseEntity<>(HttpStatus.NO_CONTENT) creates:
        //   - Status: 204 No Content
        //   - Body: Empty (Void type means no content)
        //   - Headers: (default headers only)
        //
        // ALTERNATIVE APPROACHES:
        //   - Some APIs return 200 OK with a success message
        //   - Some return the deleted resource in the body
        //   - 204 is the most RESTful approach
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }
}

/**
 * ==========================================
 * COMPLETE CRUD EXAMPLES
 * ==========================================
 *
 * SCENARIO 1: LIST ALL CATEGORIES
 * ================================
 *
 * REQUEST:
 * --------
 * GET /api/v1/categories HTTP/1.1
 * Host: localhost:8080
 * Accept: application/json
 *
 * RESPONSE:
 * ---------
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 *
 * [
 *   {
 *     "id": "123e4567-e89b-12d3-a456-426614174000",
 *     "name": "Technology",
 *     "slug": "technology"
 *   },
 *   {
 *     "id": "223e4567-e89b-12d3-a456-426614174001",
 *     "name": "Travel",
 *     "slug": "travel"
 *   }
 * ]
 *
 * CLIENT-SIDE CODE (JavaScript):
 * ------------------------------
 * fetch('http://localhost:8080/api/v1/categories')
 *   .then(response => response.json())
 *   .then(categories => {
 *     categories.forEach(cat => {
 *       console.log(`${cat.name} (${cat.slug})`);
 *     });
 *   });
 *
 *
 * SCENARIO 2: CREATE NEW CATEGORY
 * ================================
 *
 * REQUEST:
 * --------
 * POST /api/v1/categories HTTP/1.1
 * Host: localhost:8080
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 * Content-Type: application/json
 *
 * {
 *   "name": "Photography",
 *   "slug": "photography"
 * }
 *
 * RESPONSE:
 * ---------
 * HTTP/1.1 201 Created
 * Content-Type: application/json
 *
 * {
 *   "id": "323e4567-e89b-12d3-a456-426614174002",
 *   "name": "Photography",
 *   "slug": "photography"
 * }
 *
 * CLIENT-SIDE CODE (JavaScript):
 * ------------------------------
 * const token = localStorage.getItem('token');
 *
 * fetch('http://localhost:8080/api/v1/categories', {
 *   method: 'POST',
 *   headers: {
 *     'Content-Type': 'application/json',
 *     'Authorization': `Bearer ${token}`
 *   },
 *   body: JSON.stringify({
 *     name: 'Photography',
 *     slug: 'photography'
 *   })
 * })
 * .then(response => response.json())
 * .then(category => {
 *   console.log('Created category:', category.id);
 * });
 *
 *
 * SCENARIO 3: DELETE CATEGORY
 * ===========================
 *
 * REQUEST:
 * --------
 * DELETE /api/v1/categories/323e4567-e89b-12d3-a456-426614174002 HTTP/1.1
 * Host: localhost:8080
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *
 * RESPONSE:
 * ---------
 * HTTP/1.1 204 No Content
 *
 * CLIENT-SIDE CODE (JavaScript):
 * ------------------------------
 * const token = localStorage.getItem('token');
 * const categoryId = '323e4567-e89b-12d3-a456-426614174002';
 *
 * fetch(`http://localhost:8080/api/v1/categories/${categoryId}`, {
 *   method: 'DELETE',
 *   headers: {
 *     'Authorization': `Bearer ${token}`
 *   }
 * })
 * .then(response => {
 *   if (response.status === 204) {
 *     console.log('Category deleted successfully');
 *   }
 * });
 *
 *
 * ==========================================
 * VALIDATION EXAMPLE
 * ==========================================
 *
 * CreateCategoryRequest with validation:
 * --------------------------------------
 * public class CreateCategoryRequest {
 *
 *     @NotBlank(message = "Category name is required")
 *     @Size(min = 2, max = 50, message = "Name must be 2-50 characters")
 *     private String name;
 *
 *     @NotBlank(message = "Slug is required")
 *     @Pattern(regexp = "^[a-z0-9-]+$", message = "Slug must be lowercase with hyphens")
 *     private String slug;
 * }
 *
 * INVALID REQUEST:
 * ----------------
 * POST /api/v1/categories
 * {
 *   "name": "",
 *   "slug": "Invalid Slug!"
 * }
 *
 * VALIDATION ERROR RESPONSE:
 * --------------------------
 * HTTP/1.1 400 Bad Request
 * {
 *   "errors": [
 *     "Category name is required",
 *     "Slug must be lowercase with hyphens"
 *   ]
 * }
 *
 *
 * ==========================================
 * MAPPER EXAMPLE
 * ==========================================
 *
 * CategoryMapper implementation:
 * ------------------------------
 * @Component
 * public class CategoryMapper {
 *
 *     // Entity → DTO (for responses)
 *     public CategoryDto toDto(Category entity) {
 *         return CategoryDto.builder()
 *             .id(entity.getId())
 *             .name(entity.getName())
 *             .slug(entity.getSlug())
 *             // Deliberately omit: createdAt, updatedAt, posts
 *             .build();
 *     }
 *
 *     // DTO → Entity (for creation)
 *     public Category toEntity(CreateCategoryRequest dto) {
 *         return Category.builder()
 *             .name(dto.getName())
 *             .slug(dto.getSlug())
 *             // id, timestamps set by database
 *             .build();
 *     }
 * }
 *
 *
 * ==========================================
 * REST API BEST PRACTICES
 * ==========================================
 *
 * ✅ IMPLEMENTED IN THIS CONTROLLER:
 *   - Proper HTTP methods (GET, POST, DELETE)
 *   - Correct status codes (200, 201, 204)
 *   - Resource naming (plural: /categories)
 *   - Path variables for IDs
 *   - DTOs instead of entities
 *   - Validation with @Valid
 *   - Security (authentication required for mutations)
 *
 * 📋 MISSING (Could be added):
 *   - PUT/PATCH for updating categories
 *   - Pagination for list endpoint (when many categories exist)
 *   - Filtering/searching (?name=tech)
 *   - Sorting (?sort=name,asc)
 *   - HATEOAS links (links to related resources)
 *   - Rate limiting
 *   - API documentation (Swagger/OpenAPI)
 *
 *
 * ==========================================
 * TESTING TIPS
 * ==========================================
 *
 * UNIT TESTING:
 * -------------
 * @WebMvcTest(CategoryController.class)
 * class CategoryControllerTest {
 *
 *     @MockBean
 *     private CategoryService categoryService;
 *
 *     @MockBean
 *     private CategoryMapper categoryMapper;
 *
 *     @Test
 *     void shouldListCategories() {
 *         // Mock service response
 *         // Test HTTP GET
 *         // Assert status 200 and JSON array
 *     }
 * }
 *
 * INTEGRATION TESTING:
 * --------------------
 * @SpringBootTest
 * @AutoConfigureMockMvc
 * class CategoryControllerIntegrationTest {
 *
 *     @Test
 *     void shouldCreateAndDeleteCategory() {
 *         // POST new category
 *         // Verify 201 Created
 *         // DELETE the category
 *         // Verify 204 No Content
 *     }
 * }
 *
 * USING CURL:
 * -----------
 * # List categories
 * curl http://localhost:8080/api/v1/categories
 *
 * # Create category
 * curl -X POST http://localhost:8080/api/v1/categories \
 *   -H "Authorization: Bearer YOUR_TOKEN" \
 *   -H "Content-Type: application/json" \
 *   -d '{"name":"Music","slug":"music"}'
 *
 * # Delete category
 * curl -X DELETE http://localhost:8080/api/v1/categories/UUID_HERE \
 *   -H "Authorization: Bearer YOUR_TOKEN"
 */