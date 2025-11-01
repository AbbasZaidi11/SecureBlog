package org.example.controllers;

import jakarta.persistence.EntityNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.example.dtos.ApiErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;

/**
 * GLOBAL EXCEPTION HANDLER (ERROR CONTROLLER)
 * ============================================
 * PURPOSE: Centralized error handling for the entire application.
 *          Catches exceptions thrown by any controller and converts them
 *          into user-friendly JSON error responses.
 *
 * THE PROBLEM IT SOLVES:
 * ======================
 * WITHOUT this class:
 *   - Exceptions show ugly stack traces to users
 *   - Each controller needs its own try-catch blocks
 *   - Inconsistent error response formats
 *   - Security risk: exposing internal error details
 *
 * WITH this class:
 *   - All exceptions handled in ONE place
 *   - Consistent JSON error format across entire API
 *   - User-friendly error messages
 *   - Proper HTTP status codes
 *   - Sensitive details hidden from users
 *
 * ANNOTATIONS EXPLAINED:
 *
 * @RestController:
 *   - Returns JSON responses (not HTML pages)
 *   - Automatically serializes ApiErrorResponse → JSON
 *
 * @ControllerAdvice:
 *   - THIS IS THE KEY ANNOTATION!
 *   - Makes this class a "global exception handler"
 *   - Intercepts exceptions from ALL controllers
 *   - Acts as an "advice" that wraps around your controllers
 *   - Think of it as a safety net that catches all thrown exceptions
 *
 * @Slf4j (Lombok):
 *   - Automatically creates a logger instance: log
 *   - Equivalent to: private static final Logger log = LoggerFactory.getLogger(ErrorController.class);
 *   - Used for logging errors to console/files
 *
 * HOW IT WORKS:
 * =============
 * 1. Exception thrown in any controller
 * 2. Spring looks for matching @ExceptionHandler
 * 3. Executes the handler method
 * 4. Returns error response to client
 * 5. User sees clean JSON error (not stack trace)
 *
 * EXCEPTION HANDLING PRIORITY:
 * ============================
 * Spring checks handlers from MOST SPECIFIC to LEAST SPECIFIC:
 *   1. BadCredentialsException → handleBadCredentialsException()
 *   2. IllegalArgumentException → handleIllegalArgumentException()
 *   3. IllegalStateException → handleIllegalStateException()
 *   4. Any other Exception → handleException() (catch-all)
 */
@RestController
@ControllerAdvice
@Slf4j
public class ErrorController {

    /**
     * GENERIC EXCEPTION HANDLER (CATCH-ALL)
     * ======================================
     * PURPOSE: Handles ANY exception that isn't caught by more specific handlers.
     * This is your safety net for unexpected errors.
     *
     * @ExceptionHandler(Exception.class): - Catches all exceptions (Exception is the parent of all)
     * - Runs when no more specific handler exists
     * - Should be the LAST resort
     * <p>
     * WHEN THIS RUNS:
     * - NullPointerException
     * - RuntimeException
     * - Custom exceptions not handled elsewhere
     * - Database connection errors
     * - Any unexpected error
     * <p>
     * WHY RETURN 500 INTERNAL SERVER ERROR?
     * - Indicates the problem is on the server side (not client's fault)
     * - User can't fix it by changing their request
     * - Signals: "Something went wrong on our end"
     * <p>
     * ==========================================
     * EXECUTION FLOW:
     * ==========================================
     * <p>
     * SCENARIO: NullPointerException in a controller
     * -----------------------------------------------
     * <p>
     * 1. User makes request: GET /api/v1/posts/123
     * <p>
     * 2. PostController tries to process request
     * <p>
     * 3. Unexpected NullPointerException thrown:
     * Post post = postService.getPost(id);
     * String title = post.getTitle();  // ← post is null!
     * <p>
     * 4. Exception bubbles up to Spring
     * <p>
     * 5. Spring finds this handler (catches Exception.class)
     * <p>
     * 6. This method executes (see steps below)
     * <p>
     * 7. Returns error response to client
     * <p>
     * EXPECTED RESPONSE:
     * ------------------
     * HTTP/1.1 500 Internal Server Error
     * Content-Type: application/json
     * <p>
     * {
     * "status": 500,
     * "message": "An unexpected error occurred"
     * }
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleException(Exception ex) {

        // STEP 1: Log the error
        // =====================
        // log.error() writes to application logs
        //
        // WHAT GETS LOGGED:
        //   - Error message
        //   - Full stack trace (for debugging)
        //   - Timestamp
        //   - Thread name
        //
        // Example log output:
        //   2024-10-29 14:23:45 ERROR [http-nio-8080-exec-1] o.e.c.ErrorController : Caught Exception
        //   java.lang.NullPointerException: Cannot invoke "Post.getTitle()" because "post" is null
        //       at org.example.controllers.PostController.getPost(PostController.java:45)
        //       ...
        //
        // WHY LOG?
        //   - Developers need to see the actual error for debugging
        //   - Stack trace helps locate the problem in code
        //   - Log files can be analyzed later
        //   - Users shouldn't see technical details (security risk)
        log.error("Caught Exception", ex);

        // STEP 2: Build user-friendly error response
        // ===========================================
        // Create ApiErrorResponse with:
        //   - status: 500 (Internal Server Error)
        //   - message: Generic error message (safe for users)
        //
        // WHY NOT ex.getMessage()?
        //   - Exception messages can be technical: "NullPointerException at line 45"
        //   - May expose internal implementation details
        //   - Could reveal security vulnerabilities
        //   - Generic message is safer for production
        //
        // ApiErrorResponse structure:
        //   {
        //     "status": 500,
        //     "message": "An unexpected error occurred",
        //     "timestamp": "2024-10-29T14:23:45Z"  (if you add it)
        //   }
        ApiErrorResponse error = ApiErrorResponse.builder()
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())  // 500
                .message("An unexpected error occurred")
                .build();

        // STEP 3: Return error response
        // ==============================
        // ResponseEntity with:
        //   - Body: ApiErrorResponse (converted to JSON)
        //   - Status: 500 Internal Server Error
        //
        // Client receives this instead of ugly stack trace
        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * ILLEGAL ARGUMENT EXCEPTION HANDLER
     * ===================================
     * PURPOSE: Handles invalid input from the client.
     * Returns 400 Bad Request.
     *
     * @ExceptionHandler(IllegalArgumentException.class): - Catches IllegalArgumentException and its subclasses
     * - More specific than Exception.class
     * - Takes priority over generic handler
     * <p>
     * WHEN TO THROW IllegalArgumentException:
     * - Invalid function parameters
     * - Business rule violations
     * - Format errors (invalid UUID, email, etc.)
     * - Out of range values
     * <p>
     * EXAMPLE SCENARIOS:
     * - User provides negative page number: -1
     * - Invalid enum value: status=INVALID
     * - Malformed UUID: "not-a-uuid"
     * - Empty required field after validation
     * <p>
     * WHY 400 BAD REQUEST?
     * - Indicates the problem is in the CLIENT's request
     * - User needs to fix their input
     * - Server processed request correctly, but input was invalid
     * <p>
     * ==========================================
     * EXECUTION FLOW:
     * ==========================================
     * <p>
     * SCENARIO: Invalid page number
     * ------------------------------
     * <p>
     * 1. User request: GET /api/v1/posts?page=-1
     * <p>
     * 2. Controller calls: postService.listPosts(-1)
     * <p>
     * 3. Service validation:
     * if (page < 0) {
     * throw new IllegalArgumentException("Page number must be positive");
     * }
     * <p>
     * 4. Exception caught by this handler
     * <p>
     * 5. Returns error response to client
     * <p>
     * EXPECTED RESPONSE:
     * ------------------
     * HTTP/1.1 400 Bad Request
     * Content-Type: application/json
     * <p>
     * {
     * "status": 400,
     * "message": "Page number must be positive"
     * }
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex) {

        // Build error response with exception's message
        // ==============================================
        // USING ex.getMessage() HERE IS SAFE because:
        //   - You control the exception messages in your code
        //   - Messages are designed to be user-friendly
        //   - No sensitive information exposed
        //
        // Example messages:
        //   - "Invalid UUID format"
        //   - "Page size must be between 1 and 100"
        //   - "Category name cannot be empty"
        ApiErrorResponse error = ApiErrorResponse.builder()
                .status(HttpStatus.BAD_REQUEST.value())  // 400
                .message(ex.getMessage())  // Use the actual error message
                .build();

        // Return 400 Bad Request
        // ======================
        // Tells client: "Your request was invalid, please fix it"
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    /**
     * ILLEGAL STATE EXCEPTION HANDLER
     * ================================
     * PURPOSE: Handles operations that cannot be performed due to current state.
     * Returns 409 Conflict.
     *
     * @ExceptionHandler(IllegalStateException.class): - Catches IllegalStateException and its subclasses
     * - For state-related problems
     * <p>
     * WHEN TO THROW IllegalStateException:
     * - Resource already exists (duplicate)
     * - Operation not allowed in current state
     * - Constraint violations
     * - Business logic prevents the action
     * <p>
     * EXAMPLE SCENARIOS:
     * - Creating category with slug that already exists
     * - Deleting category that has posts
     * - Publishing a post that's already published
     * - Registering with email that's already taken
     * - Archiving an already archived item
     * <p>
     * WHY 409 CONFLICT?
     * - Indicates request conflicts with current state of resource
     * - Request was valid, but cannot be completed now
     * - Client needs to resolve the conflict first
     * - Different from 400 (which is about invalid input)
     * <p>
     * 409 vs 400 vs 422:
     * - 400: Syntax/format error (invalid JSON, missing field)
     * - 409: Conflict with current state (duplicate, constraint)
     * - 422: Valid format but semantically incorrect (future date in past)
     * <p>
     * ==========================================
     * EXECUTION FLOW:
     * ==========================================
     * <p>
     * SCENARIO: Creating duplicate category
     * --------------------------------------
     * <p>
     * 1. User request:
     * POST /api/v1/categories
     * { "name": "Technology", "slug": "technology" }
     * <p>
     * 2. Controller calls: categoryService.createCategory(category)
     * <p>
     * 3. Service checks for duplicates:
     * if (categoryRepository.existsBySlug(slug)) {
     * throw new IllegalStateException("Category with slug 'technology' already exists");
     * }
     * <p>
     * 4. Exception caught by this handler
     * <p>
     * 5. Returns error response to client
     * <p>
     * EXPECTED RESPONSE:
     * ------------------
     * HTTP/1.1 409 Conflict
     * Content-Type: application/json
     * <p>
     * {
     * "status": 409,
     * "message": "Category with slug 'technology' already exists"
     * }
     */
    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ApiErrorResponse> handleIllegalStateException(IllegalStateException ex) {

        // Build error response
        // ====================
        // Uses exception's message (which should explain the conflict)
        //
        // Example messages:
        //   - "Category already exists"
        //   - "Cannot delete category with existing posts"
        //   - "Email already registered"
        //   - "Post is already published"
        ApiErrorResponse error = ApiErrorResponse.builder()
                .status(HttpStatus.CONFLICT.value())  // 409
                .message(ex.getMessage())
                .build();

        // Return 409 Conflict
        // ===================
        // Tells client: "Request conflicts with current state, resolve conflict first"
        return new ResponseEntity<>(error, HttpStatus.CONFLICT);
    }

    /**
     * BAD CREDENTIALS EXCEPTION HANDLER
     * ==================================
     * PURPOSE: Handles authentication failures (wrong username/password).
     * Returns 401 Unauthorized.
     *
     * @ExceptionHandler(BadCredentialsException.class): - Catches Spring Security's BadCredentialsException
     * - Thrown during login when credentials don't match
     * <p>
     * WHEN THIS IS THROWN:
     * - Wrong password during login
     * - Non-existent email during login
     * - Expired credentials
     * - Account locked/disabled
     * <p>
     * WHERE IT COMES FROM:
     * - AuthenticationManager.authenticate() in AuthenticationService
     * - DaoAuthenticationProvider when password check fails
     * - UserDetailsService when user not found
     * <p>
     * WHY 401 UNAUTHORIZED?
     * - Standard HTTP code for authentication failures
     * - Means: "You need valid credentials to access this"
     * - Client should prompt user to login again
     * - Not 403 Forbidden (which means authenticated but not authorized)
     * <p>
     * 401 vs 403:
     * - 401 Unauthorized: "Who are you? Please login"
     * - 403 Forbidden: "I know who you are, but you can't do this"
     * <p>
     * ==========================================
     * EXECUTION FLOW:
     * ==========================================
     * <p>
     * SCENARIO: User enters wrong password
     * -------------------------------------
     * <p>
     * 1. User request:
     * POST /api/v1/auth
     * { "email": "user@test.com", "password": "wrongpassword" }
     * <p>
     * 2. AuthController calls: authenticationService.authenticate(email, password)
     * <p>
     * 3. AuthenticationService calls: authenticationManager.authenticate(token)
     * <p>
     * 4. DaoAuthenticationProvider:
     * - Loads user from database
     * - Compares passwords with PasswordEncoder
     * - Passwords don't match!
     * - Throws BadCredentialsException
     * <p>
     * 5. Exception bubbles up to this handler
     * <p>
     * 6. Returns error response to client
     * <p>
     * EXPECTED RESPONSE:
     * ------------------
     * HTTP/1.1 401 Unauthorized
     * Content-Type: application/json
     * <p>
     * {
     * "status": 401,
     * "message": "Bad credentials"
     * }
     * <p>
     * SECURITY NOTE:
     * --------------
     * The message "Bad credentials" is intentionally vague:
     * - Doesn't reveal if email exists or password is wrong
     * - Prevents attackers from enumerating valid emails
     * - Good security practice: don't leak information
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiErrorResponse> handleBadCredentialsException(BadCredentialsException ex) {

        // Build error response
        // ====================
        // Uses Spring Security's exception message
        // Usually: "Bad credentials" (intentionally vague for security)
        ApiErrorResponse error = ApiErrorResponse.builder()
                .status(HttpStatus.UNAUTHORIZED.value())  // 401
                .message(ex.getMessage())
                .build();

        // Return 401 Unauthorized
        // =======================
        // Tells client: "Authentication failed, please login again"
        //
        // CLIENT SHOULD:
        //   - Clear stored token (if any)
        //   - Redirect to login page
        //   - Show error message to user
        //   - Allow user to retry with correct credentials
        return new ResponseEntity<>(error, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleEntityNotFoundException(EntityNotFoundException ex) {
        ApiErrorResponse error = ApiErrorResponse.builder()
                .status(HttpStatus.NOT_FOUND.value())  // 401
                .message(ex.getMessage())
                .build();

        return new ResponseEntity<>(error, HttpStatus.NOT_FOUND);
    }
}


/**
 * ==========================================
 * ERROR HANDLING EXAMPLES
 * ==========================================
 *
 * EXAMPLE 1: AUTHENTICATION FAILURE
 * ==================================
 *
 * CLIENT REQUEST:
 * ---------------
 * POST /api/v1/auth HTTP/1.1
 * Content-Type: application/json
 *
 * {
 *   "email": "user@test.com",
 *   "password": "wrongpassword"
 * }
 *
 * WHAT HAPPENS:
 * -------------
 * 1. AuthController receives request
 * 2. Calls authenticationService.authenticate()
 * 3. Password doesn't match → BadCredentialsException
 * 4. ErrorController.handleBadCredentialsException() catches it
 * 5. Returns 401 response
 *
 * SERVER RESPONSE:
 * ----------------
 * HTTP/1.1 401 Unauthorized
 * Content-Type: application/json
 *
 * {
 *   "status": 401,
 *   "message": "Bad credentials"
 * }
 *
 *
 * EXAMPLE 2: DUPLICATE CATEGORY
 * ==============================
 *
 * CLIENT REQUEST:
 * ---------------
 * POST /api/v1/categories HTTP/1.1
 * Authorization: Bearer eyJhbGci...
 * Content-Type: application/json
 *
 * {
 *   "name": "Technology",
 *   "slug": "technology"
 * }
 *
 * WHAT HAPPENS:
 * -------------
 * 1. CategoryController receives request
 * 2. Calls categoryService.createCategory()
 * 3. Service checks: slug already exists!
 * 4. Throws IllegalStateException("Category already exists")
 * 5. ErrorController.handleIllegalStateException() catches it
 * 6. Returns 409 response
 *
 * SERVER RESPONSE:
 * ----------------
 * HTTP/1.1 409 Conflict
 * Content-Type: application/json
 *
 * {
 *   "status": 409,
 *   "message": "Category already exists"
 * }
 *
 *
 * EXAMPLE 3: INVALID PAGE NUMBER
 * ===============================
 *
 * CLIENT REQUEST:
 * ---------------
 * GET /api/v1/posts?page=-1 HTTP/1.1
 *
 * WHAT HAPPENS:
 * -------------
 * 1. PostController receives request
 * 2. Calls postService.listPosts(-1)
 * 3. Service validates: page < 0 is invalid
 * 4. Throws IllegalArgumentException("Page must be positive")
 * 5. ErrorController.handleIllegalArgumentException() catches it
 * 6. Returns 400 response
 *
 * SERVER RESPONSE:
 * ----------------
 * HTTP/1.1 400 Bad Request
 * Content-Type: application/json
 *
 * {
 *   "status": 400,
 *   "message": "Page must be positive"
 * }
 *
 *
 * EXAMPLE 4: UNEXPECTED ERROR
 * ============================
 *
 * CLIENT REQUEST:
 * ---------------
 * GET /api/v1/posts/123 HTTP/1.1
 *
 * WHAT HAPPENS:
 * -------------
 * 1. PostController receives request
 * 2. Database connection fails (unexpected!)
 * 3. SQLException thrown
 * 4. No specific handler for SQLException
 * 5. ErrorController.handleException() catches it (generic handler)
 * 6. Logs full error for developers
 * 7. Returns 500 with generic message (doesn't expose details)
 *
 * SERVER RESPONSE:
 * ----------------
 * HTTP/1.1 500 Internal Server Error
 * Content-Type: application/json
 *
 * {
 *   "status": 500,
 *   "message": "An unexpected error occurred"
 * }
 *
 * SERVER LOGS (visible to developers):
 * -------------------------------------
 * 2024-10-29 14:30:00 ERROR o.e.c.ErrorController : Caught Exception
 * java.sql.SQLException: Connection timeout
 *     at org.postgresql.jdbc.PgConnection.executeQuery(...)
 *     at org.example.repositories.PostRepository.findById(...)
 *     ...
 *
 *
 * ==========================================
 * API ERROR RESPONSE DTO
 * ==========================================
 *
 * Example ApiErrorResponse class:
 * --------------------------------
 * @Data
 * @Builder
 * public class ApiErrorResponse {
 *     private int status;           // HTTP status code
 *     private String message;       // User-friendly error message
 *     private LocalDateTime timestamp;  // When error occurred (optional)
 *     private String path;          // Request path (optional)
 *     private List<String> errors;  // Multiple errors (optional, for validation)
 * }
 *
 *
 * ==========================================
 * EXTENDING THIS ERROR HANDLER
 * ==========================================
 *
 * ADD MORE SPECIFIC HANDLERS:
 * ---------------------------
 *
 * // Handle resource not found
 * @ExceptionHandler(EntityNotFoundException.class)
 * public ResponseEntity<ApiErrorResponse> handleNotFound(EntityNotFoundException ex) {
 *     return new ResponseEntity<>(
 *         ApiErrorResponse.builder()
 *             .status(404)
 *             .message(ex.getMessage())
 *             .build(),
 *         HttpStatus.NOT_FOUND
 *     );
 * }
 *
 * // Handle validation errors
 * @ExceptionHandler(MethodArgumentNotValidException.class)
 * public ResponseEntity<ApiErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
 *     List<String> errors = ex.getBindingResult()
 *         .getFieldErrors()
 *         .stream()
 *         .map(FieldError::getDefaultMessage)
 *         .toList();
 *
 *     return new ResponseEntity<>(
 *         ApiErrorResponse.builder()
 *             .status(400)
 *             .message("Validation failed")
 *             .errors(errors)
 *             .build(),
 *         HttpStatus.BAD_REQUEST
 *     );
 * }
 *
 * // Handle access denied (authorization)
 * @ExceptionHandler(AccessDeniedException.class)
 * public ResponseEntity<ApiErrorResponse> handleAccessDenied(AccessDeniedException ex) {
 *     return new ResponseEntity<>(
 *         ApiErrorResponse.builder()
 *             .status(403)
 *             .message("Access denied")
 *             .build(),
 *         HttpStatus.FORBIDDEN
 *     );
 * }
 *
 *
 * ==========================================
 * HTTP STATUS CODES QUICK REFERENCE
 * ==========================================
 *
 * SUCCESS (2xx):
 *   200 OK              - Request succeeded
 *   201 Created         - Resource created successfully
 *   204 No Content      - Success with no response body
 *
 * CLIENT ERRORS (4xx):
 *   400 Bad Request     - Invalid input/format
 *   401 Unauthorized    - Authentication required/failed
 *   403 Forbidden       - Authenticated but not authorized
 *   404 Not Found       - Resource doesn't exist
 *   409 Conflict        - Request conflicts with current state
 *   422 Unprocessable   - Valid format but semantically incorrect
 *   429 Too Many Requests - Rate limit exceeded
 *
 * SERVER ERRORS (5xx):
 *   500 Internal Server Error - Unexpected server error
 *   502 Bad Gateway          - Invalid response from upstream
 *   503 Service Unavailable  - Server temporarily unavailable
 *
 *
 * ==========================================
 * BEST PRACTICES
 * ==========================================
 *
 * ✅ CURRENT IMPLEMENTATION DOES:
 *   - Centralized error handling
 *   - Consistent JSON error format
 *   - Proper HTTP status codes
 *   - Logging for debugging
 *   - Safe error messages for users
 *   - Specific handlers for common exceptions
 *
 * 🔒 SECURITY RECOMMENDATIONS:
 *   - Never expose stack traces to users (✓ done)
 *   - Don't reveal internal implementation details (✓ done)
 *   - Use vague messages for auth failures (✓ done)
 *   - Log detailed errors server-side only (✓ done)
 *   - Consider rate limiting on error responses
 *   - Don't include sensitive data in error messages
 *
 * 📋 ADDITIONAL IMPROVEMENTS:
 *   - Add timestamp to error responses
 *   - Include request path/ID for debugging
 *   - Add correlation IDs for distributed tracing
 *   - Implement different error responses for dev/prod
 *   - Add metrics/monitoring for error rates
 *   - Create custom exception classes for business logic
 *   - Add validation error details (field-level errors)
 *
 *
 * ==========================================
 * CLIENT-SIDE ERROR HANDLING
 * ==========================================
 *
 * JavaScript example:
 * -------------------
 * fetch('/api/v1/categories', {
 *   method: 'POST',
 *   headers: {
 *     'Content-Type': 'application/json',
 *     'Authorization': `Bearer ${token}`
 *   },
 *   body: JSON.stringify({ name: 'Tech', slug: 'tech' })
 * })
 * .then(response => {
 *   if (!response.ok) {
 *     return response.json().then(error => {
 *       // Handle error based on status code
 *       switch (error.status) {
 *         case 400:
 *           console.error('Invalid input:', error.message);
 *           break;
 *         case 401:
 *           console.error('Please login again');
 *           redirectToLogin();
 *           break;
 *         case 409:
 *           console.error('Already exists:', error.message);
 *           break;
 *         case 500:
 *           console.error('Server error, try again later');
 *           break;
 *       }
 *       throw error;
 *     });
 *   }
 *   return response.json();
 * })
 * .then(data => {
 *   console.log('Success:', data);
 * })
 * .catch(error => {
 *   console.error('Request failed:', error);
 * });
 */