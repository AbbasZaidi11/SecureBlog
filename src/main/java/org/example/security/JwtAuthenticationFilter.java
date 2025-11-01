package org.example.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.services.AuthenticationService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT AUTHENTICATION FILTER
 * ==========================
 * PURPOSE: This is the "security guard" of your application.
 *          It intercepts EVERY incoming HTTP request and checks for JWT tokens.
 *
 * WHAT IS A FILTER?
 * =================
 * Filters are like checkpoints in a pipeline. Every HTTP request goes through filters
 * BEFORE reaching your controllers.
 *
 * Request Flow:
 * ============
 * Client → Filter1 → Filter2 → JwtAuthenticationFilter → Filter4 → Controller
 *                                      ↑
 *                                  YOU ARE HERE
 *
 * OncePerRequestFilter:
 * ---------------------
 * - Guarantees filter runs exactly ONCE per request
 * - Even with forwards/includes, won't run multiple times
 * - Perfect for authentication (don't want to authenticate twice!)
 *
 * WHEN THIS RUNS:
 * ===============
 * ✓ GET /api/v1/posts              → Runs
 * ✓ POST /api/v1/categories        → Runs
 * ✓ DELETE /api/v1/posts/123       → Runs
 * ✓ POST /api/v1/auth (login)      → Runs (but no token expected)
 *
 * Literally EVERY request passes through here!
 *
 * WHAT IT DOES:
 * =============
 * 1. Extracts JWT token from Authorization header
 * 2. Validates token (checks signature, expiration)
 * 3. Loads user information
 * 4. Sets authentication in Spring Security context
 * 5. Allows request to continue to controller
 *
 * IF TOKEN INVALID:
 * - Doesn't set authentication
 * - Request continues but as "anonymous"
 * - Spring Security will reject if endpoint requires authentication
 *
 * @RequiredArgsConstructor (Lombok):
 *   - Auto-generates constructor for 'final' fields
 *   - Spring injects AuthenticationService dependency
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /**
     * DEPENDENCY: AUTHENTICATION SERVICE
     * ==================================
     * This service handles JWT token validation and user loading.
     *
     * Contains methods:
     * - validateToken(token) → validates and returns UserDetails
     * - generateToken(userDetails) → creates JWT tokens
     * - authenticate(email, password) → verifies login credentials
     */
    private final AuthenticationService authenticationService;

    /**
     * MAIN FILTER METHOD
     * ==================
     * This method is called by Spring for EVERY HTTP request.
     *
     * PARAMETERS:
     * -----------
     * @param request - The incoming HTTP request
     *                  Contains: headers, body, URL, method, etc.
     *
     * @param response - The HTTP response to send back
     *                   Can modify: status code, headers, body
     *
     * @param filterChain - The chain of remaining filters
     *                      Call filterChain.doFilter() to continue processing
     *
     * CRITICAL RULE:
     * --------------
     * MUST call filterChain.doFilter() at the end!
     * If you forget, request stops here and never reaches controller.
     *
     * ==========================================
     * EXECUTION FLOW FOR EVERY REQUEST:
     * ==========================================
     *
     * SCENARIO 1: REQUEST WITH VALID TOKEN
     * -------------------------------------
     * Client sends:
     *   GET /api/v1/posts
     *   Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
     *
     * Flow:
     * 1. This filter runs first
     * 2. Extracts token from header
     * 3. Validates token (signature, expiration)
     * 4. Sets authentication in SecurityContext
     * 5. Calls filterChain.doFilter() → continues to controller
     * 6. Controller executes normally
     * 7. Returns response
     *
     *
     * SCENARIO 2: REQUEST WITH INVALID/EXPIRED TOKEN
     * -----------------------------------------------
     * Client sends:
     *   GET /api/v1/posts
     *   Authorization: Bearer <expired_or_invalid_token>
     *
     * Flow:
     * 1. This filter runs
     * 2. Extracts token
     * 3. Validation fails (exception thrown)
     * 4. Catch block: logs warning, doesn't set authentication
     * 5. Calls filterChain.doFilter() → continues
     * 6. Spring Security checks: no authentication set
     * 7. Endpoint requires authentication → 401 Unauthorized
     * 8. Controller never reached
     *
     *
     * SCENARIO 3: REQUEST WITHOUT TOKEN (PUBLIC ENDPOINT)
     * ----------------------------------------------------
     * Client sends:
     *   GET /api/v1/posts  (no Authorization header)
     *
     * Flow:
     * 1. This filter runs
     * 2. extractToken() returns null (no header)
     * 3. if (token != null) → false, skips authentication
     * 4. Calls filterChain.doFilter() → continues
     * 5. Spring Security checks endpoint configuration
     * 6. If permitAll() → allows request (controller executes)
     * 7. If authenticated() → 401 Unauthorized
     *
     *
     * SCENARIO 4: LOGIN REQUEST (NO TOKEN EXPECTED)
     * ----------------------------------------------
     * Client sends:
     *   POST /api/v1/auth
     *   { "email": "user@test.com", "password": "password" }
     *
     * Flow:
     * 1. This filter runs
     * 2. No Authorization header → token is null
     * 3. Skips authentication block
     * 4. Calls filterChain.doFilter() → continues
     * 5. Reaches AuthController.login()
     * 6. Controller authenticates and generates token
     * 7. Returns token to client
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // STEP 1: TRY-CATCH BLOCK
        // =======================
        // Why wrap in try-catch?
        // - Token validation can throw exceptions (expired, invalid, etc.)
        // - Don't want filter to crash and break the entire request
        // - If token invalid, just continue without authentication
        // - Spring Security will handle rejection later
        try {

            // STEP 2: EXTRACT TOKEN FROM REQUEST
            // ===================================
            // extractToken() looks for "Authorization: Bearer <token>" header
            // Returns: token string or null if not present
            //
            // Example header values:
            //   Valid: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            //   Invalid: "eyJ..." (missing "Bearer " prefix)
            //   Invalid: "Basic dXNlcjpwYXNz" (wrong auth type)
            //   Missing: null (no Authorization header)
            String token = extractToken(request);

            // STEP 3: CHECK IF TOKEN EXISTS
            // ==============================
            // token != null means:
            //   ✓ Authorization header was present
            //   ✓ It started with "Bearer "
            //   ✓ We extracted the token part
            //
            // If null:
            //   - Skip authentication (no token provided)
            //   - Could be public endpoint or unauthenticated request
            //   - Let Spring Security decide if endpoint requires auth
            if (token != null) {

                // STEP 4: VALIDATE TOKEN AND LOAD USER
                // =====================================
                // authenticationService.validateToken() does:
                //   a) Parses JWT token
                //   b) Verifies signature (proves token is authentic)
                //   c) Checks expiration (throws exception if expired)
                //   d) Extracts username from token
                //   e) Loads UserDetails from database
                //   f) Returns UserDetails
                //
                // WHAT IS UserDetails?
                //   Spring Security's interface for user information
                //   Your BlogUserDetails implements this interface
                //
                // Contains:
                //   - username (email)
                //   - password (hashed, not used here)
                //   - authorities (roles like ROLE_USER, ROLE_ADMIN)
                //   - enabled, locked, expired flags
                //
                // EXCEPTIONS THAT CAN BE THROWN:
                //   - ExpiredJwtException: Token expired
                //   - SignatureException: Token signature invalid (tampered)
                //   - MalformedJwtException: Token format wrong
                //   - UsernameNotFoundException: User deleted from database
                UserDetails userDetails = authenticationService.validateToken(token);

                // STEP 5: CREATE AUTHENTICATION OBJECT
                // =====================================
                // THIS IS "STEP 3" FROM YOUR QUESTION!
                // This is THE KEY STEP that sets up authentication!
                //
                // UsernamePasswordAuthenticationToken is Spring Security's
                // way of representing an authenticated user.
                //
                // Three parameters:
                // 1. principal (userDetails): WHO is authenticated
                // 2. credentials (null): password (not needed, already verified via JWT)
                // 3. authorities: WHAT they can do (roles/permissions)
                //
                // WHAT IS "principal"?
                //   The user object representing the authenticated user
                //   Can be accessed later in controllers via:
                //     - SecurityContextHolder.getContext().getAuthentication().getPrincipal()
                //     - @AuthenticationPrincipal annotation
                //
                // WHY null FOR credentials?
                //   - credentials = password in typical username/password auth
                //   - With JWT, we already verified user (token signature valid)
                //   - No need to store password in memory
                //   - Security best practice: don't keep passwords around
                //
                // WHAT ARE authorities?
                //   - Roles and permissions: ["ROLE_USER", "ROLE_ADMIN", "WRITE_POST"]
                //   - Used by Spring Security for authorization
                //   - Checked against @PreAuthorize, @Secured annotations
                //   - Example: @PreAuthorize("hasRole('ADMIN')") needs ROLE_ADMIN in authorities
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails,                    // Principal: the user
                        null,                           // Credentials: no password needed
                        userDetails.getAuthorities()    // Authorities: roles/permissions
                );

                // STEP 6: SET AUTHENTICATION IN SECURITY CONTEXT
                // ===============================================
                // THIS IS THE CRITICAL STEP! (THE "STEP 3" FROM YOUR QUESTION!)
                //
                // SecurityContextHolder is like a global storage for the current request.
                // Think of it as a backpack that travels with this HTTP request.
                //
                // BEFORE this line:
                //   - Token is valid ✓
                //   - User loaded from database ✓
                //   - BUT Spring Security doesn't know user is authenticated ✗
                //   - SecurityContext is empty
                //
                // AFTER this line:
                //   - Spring Security KNOWS user is authenticated ✓
                //   - SecurityContext contains authentication object ✓
                //   - Controllers can access current user ✓
                //   - Authorization checks will pass ✓
                //
                // WHAT HAPPENS:
                // -------------
                // SecurityContextHolder.getContext() → Gets the SecurityContext for THIS request
                // .setAuthentication(authentication) → Puts our authentication object in it
                //
                // Now Spring Security knows:
                //   ✓ User is authenticated
                //   ✓ Username is "user@test.com"
                //   ✓ User has [ROLE_USER] role
                //   ✓ User can access protected endpoints
                //
                // ANALOGY:
                // --------
                // Token validation = Security guard checks your ID
                // This line = Security guard gives you a wristband
                // Wristband = Everyone in the building can see you're allowed to be here
                //
                // Without this line, it's like the guard said "your ID is valid" but
                // never gave you a wristband, so nobody inside knows you're allowed in!
                SecurityContextHolder.getContext().setAuthentication(authentication);

                // COMMENTED CODE (For reference - shows how to access authentication):
                // ====================================================================
                // After setting authentication, you can access it anywhere:
                //
                // Authentication auth = SecurityContextHolder.getContext().getAuthentication();
                // String email = auth.getName();  // Gets the username (email)
                //
                // This is how controllers can know WHO is making the request.
                // You'll use this pattern to get current user in your services/controllers.

                // STEP 7: STORE USER ID IN REQUEST ATTRIBUTE (OPTIONAL OPTIMIZATION)
                // ===================================================================
                // This is a clever optimization!
                //
                // WHY DO THIS?
                // ------------
                // Sometimes you need just the user ID (not full UserDetails)
                // Instead of casting UserDetails everywhere, store ID once here
                // Controllers can access via request.getAttribute("userId")
                //
                // HOW IT WORKS:
                // -------------
                // BlogUserDetails is YOUR custom implementation of UserDetails
                // It extends Spring's UserDetails and adds getId() method
                //
                // instanceof check:
                //   - Checks if userDetails is actually a BlogUserDetails
                //   - Type-safe way to ensure casting won't fail
                //   - If it's not BlogUserDetails, skip this step
                //
                // Casting:
                //   ((BlogUserDetails) userDetails) → converts UserDetails to BlogUserDetails
                //   .getId() → gets the user's ID from database
                //
                // request.setAttribute():
                //   - Stores ID in the HTTP request object
                //   - Available to controllers and other filters
                //   - Scoped to this request only (not shared across requests)
                //
                // USAGE IN CONTROLLER:
                // --------------------
                // @GetMapping("/my-posts")
                // public List<Post> getMyPosts(HttpServletRequest request) {
                //     UUID userId = (UUID) request.getAttribute("userId");
                //     return postService.findByUserId(userId);
                // }
                //
                // ALTERNATIVE WITHOUT THIS:
                // -------------------------
                // @GetMapping("/my-posts")
                // public List<Post> getMyPosts(@AuthenticationPrincipal BlogUserDetails user) {
                //     UUID userId = user.getId();  // Need to cast every time
                //     return postService.findByUserId(userId);
                // }
                if (userDetails instanceof BlogUserDetails) {
                    request.setAttribute("userId", ((BlogUserDetails) userDetails).getId());
                }
            }

        } catch (Exception ex) {
            // STEP 8: EXCEPTION HANDLING
            // ===========================
            // If ANYTHING goes wrong during token validation:
            //   - Token expired (ExpiredJwtException)
            //   - Token tampered (SignatureException)
            //   - Token malformed (MalformedJwtException)
            //   - User not found (UsernameNotFoundException)
            //   - Any other error
            //
            // WHAT WE DO:
            //   - Log a warning (for debugging)
            //   - DON'T set authentication in SecurityContext
            //   - DON'T throw exception (let request continue)
            //
            // WHY NOT THROW EXCEPTION?
            //   - Filter should not crash the entire request
            //   - Let Spring Security handle authentication failures
            //   - Request continues to SecurityFilterChain
            //   - Spring Security will return 401 if endpoint requires auth
            //
            // logger.warn():
            //   - Writes to application logs
            //   - "warn" level = something wrong but not critical
            //   - Helps debug authentication issues
            //   - Example log: "2024-10-29 10:30:45 WARN ... Received invalid auth token"
            //
            // RESULT:
            //   - SecurityContext remains empty (no authentication set)
            //   - Request is treated as "anonymous"
            //   - If endpoint requires auth → Spring Security returns 401
            //   - If endpoint is public → request proceeds normally
            logger.warn("Received invalid auth token");
        }

        // STEP 9: CONTINUE FILTER CHAIN
        // ==============================
        // THIS LINE IS CRITICAL - NEVER FORGET IT!
        //
        // filterChain.doFilter() means:
        //   "I'm done, pass the request to the next filter (or controller)"
        //
        // What happens next:
        //   1. Other Spring Security filters run
        //   2. FilterSecurityInterceptor checks if user is authenticated
        //   3. If authenticated → request reaches controller
        //   4. If not authenticated + endpoint requires auth → 401 Unauthorized
        //   5. Controller executes (if allowed)
        //   6. Response travels back through filters
        //   7. Returns to client
        //
        // IF YOU FORGET THIS LINE:
        //   ❌ Request stops here
        //   ❌ Controller never reached
        //   ❌ Client hangs waiting for response
        //   ❌ Eventually timeout error
        //
        // PARAMETERS:
        //   request - Forward the same request object
        //   response - Forward the same response object
        //
        // This line ALWAYS executes:
        //   - Even if token was invalid (caught in catch block)
        //   - Even if no token was provided
        //   - Even if exception occurred
        //   - That's why it's outside the try-catch
        filterChain.doFilter(request, response);
    }

    /**
     * EXTRACT TOKEN FROM REQUEST (PRIVATE HELPER METHOD)
     * ===================================================
     * PURPOSE: Extracts JWT token from the Authorization header.
     *
     * PARAMETERS:
     *   @param request - HTTP request containing headers
     *
     * RETURNS:
     *   String - The JWT token (without "Bearer " prefix)
     *   null - If no token found or invalid format
     *
     * HTTP HEADER FORMAT:
     * ===================
     * Standard format for JWT authentication:
     *   Authorization: Bearer <token>
     *
     * Example:
     *   Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI...
     *
     * "Bearer" is the authentication scheme:
     *   - Indicates token-based authentication
     *   - Standard defined in OAuth 2.0 (RFC 6750)
     *   - Space after "Bearer" is required
     *   - Case-sensitive (must be "Bearer", not "bearer")
     *
     * OTHER AUTH SCHEMES (not used here):
     *   - Basic: Base64(username:password)
     *   - Digest: Hash-based authentication
     *   - OAuth: OAuth tokens
     */
    private String extractToken(HttpServletRequest request) {

        // STEP 1: GET AUTHORIZATION HEADER
        // =================================
        // request.getHeader("Authorization") retrieves the header value
        //
        // Header names are case-insensitive in HTTP:
        //   "Authorization" = "authorization" = "AUTHORIZATION"
        //
        // Possible values:
        //   "Bearer eyJhbGci..." → Valid JWT token
        //   "Basic dXNlcjpw..." → Basic auth (not JWT, return null)
        //   null → No Authorization header present
        //   "" → Empty string (rare, but possible)
        String bearerToken = request.getHeader("Authorization");

        // STEP 2: VALIDATE AND EXTRACT TOKEN
        // ===================================
        // Two conditions must be true:
        // 1. bearerToken != null → Header exists
        // 2. bearerToken.startsWith("Bearer ") → Correct format
        //
        // WHY CHECK startsWith("Bearer ")?
        //   - Ensures it's a Bearer token (not Basic, Digest, etc.)
        //   - Space after "Bearer" is part of the standard
        //   - Prevents accepting malformed headers
        //
        // EXAMPLES:
        // ---------
        // Valid:
        //   "Bearer eyJ..." → passes check ✓
        //
        // Invalid (returns null):
        //   null → bearerToken is null ✗
        //   "" → doesn't start with "Bearer " ✗
        //   "Bearer" → no space after Bearer ✗
        //   "bearer eyJ..." → lowercase b ✗
        //   "Basic dXNlcjpwYXNz" → different auth scheme ✗
        //   "eyJ..." → missing "Bearer " prefix ✗
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {

            // STEP 3: EXTRACT TOKEN PART
            // ===========================
            // substring(7) removes first 7 characters: "Bearer "
            //
            // BREAKDOWN:
            // ----------
            // String: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            // Index:   0123456789...
            //          ^      ^
            //          0      7
            //
            // .substring(7) means: "start at index 7, take everything after"
            //
            // Result: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            //         (just the token, no "Bearer " prefix)
            //
            // WHY 7?
            //   B e a r e r   <space>
            //   0 1 2 3 4 5 6  7
            //   Total: 7 characters to skip
            //
            // ALTERNATIVE (more readable but same result):
            //   bearerToken.replace("Bearer ", "")
            //   But substring(7) is faster (no searching needed)
            return bearerToken.substring(7);
        }

        // STEP 4: RETURN NULL IF INVALID
        // ===============================
        // If we reach here, one of these is true:
        //   - No Authorization header (bearerToken is null)
        //   - Header exists but doesn't start with "Bearer "
        //
        // Returning null tells the caller:
        //   "No valid JWT token found in this request"
        //
        // The doFilterInternal() method will:
        //   - Check if (token != null)
        //   - Skip authentication if null
        //   - Let request continue without setting authentication
        return null;
    }
}

/**
 * ==========================================
 * COMPLETE REQUEST FLOW EXAMPLES
 * ==========================================
 *
 * EXAMPLE 1: SUCCESSFUL AUTHENTICATED REQUEST
 * ============================================
 *
 * CLIENT SENDS:
 * -------------
 * GET /api/v1/posts HTTP/1.1
 * Host: localhost:8080
 * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI6InVzZXJAdGVzdC5jb20iLCJpYXQiOjE2MzUwMDAwMDAsImV4cCI6MTYzNTA4NjQwMH0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
 *
 * FILTER EXECUTION:
 * -----------------
 * 1. doFilterInternal() called
 * 2. extractToken() → returns "eyJhbGci..."
 * 3. token != null → true, enter if block
 * 4. authenticationService.validateToken():
 *    - Parses JWT
 *    - Verifies signature ✓
 *    - Checks expiration ✓
 *    - Extracts username: "user@test.com"
 *    - Queries database: SELECT * FROM users WHERE email = 'user@test.com'
 *    - Returns UserDetails
 * 5. Create UsernamePasswordAuthenticationToken
 * 6. SecurityContextHolder.getContext().setAuthentication() → USER IS NOW AUTHENTICATED!
 * 7. Store userId in request attribute
 * 8. filterChain.doFilter() → continue to controller
 * 9. PostController.getPosts() executes
 * 10. Returns response
 *
 * SERVER RESPONDS:
 * ----------------
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 *
 * {
 *   "posts": [...]
 * }
 *
 *
 * EXAMPLE 2: EXPIRED TOKEN
 * ========================
 *
 * CLIENT SENDS:
 * -------------
 * GET /api/v1/posts HTTP/1.1
 * Authorization: Bearer <token_from_25_hours_ago>
 *
 * FILTER EXECUTION:
 * -----------------
 * 1. doFilterInternal() called
 * 2. extractToken() → returns expired token
 * 3. token != null → true, enter if block
 * 4. authenticationService.validateToken():
 *    - Parses JWT
 *    - Verifies signature ✓
 *    - Checks expiration: current time > expiration time
 *    - Throws ExpiredJwtException
 * 5. catch block: logger.warn("Received invalid auth token")
 * 6. Authentication NOT set (SecurityContext stays empty)
 * 7. filterChain.doFilter() → continue
 * 8. Spring Security checks: no authentication set
 * 9. Endpoint requires auth → reject request
 *
 * SERVER RESPONDS:
 * ----------------
 * HTTP/1.1 401 Unauthorized
 * Content-Type: application/json
 *
 * {
 *   "status": 401,
 *   "message": "Token expired"
 * }
 *
 *
 * EXAMPLE 3: NO TOKEN (PUBLIC ENDPOINT)
 * ======================================
 *
 * CLIENT SENDS:
 * -------------
 * GET /api/v1/posts HTTP/1.1
 * (No Authorization header)
 *
 * FILTER EXECUTION:
 * -----------------
 * 1. doFilterInternal() called
 * 2. extractToken() → returns null (no header)
 * 3. token != null → false, skip if block
 * 4. Authentication NOT set
 * 5. filterChain.doFilter() → continue
 * 6. Spring Security checks SecurityConfig:
 *    .requestMatchers(HttpMethod.GET, "/api/v1/posts/**").permitAll()
 * 7. Endpoint is public → allow request
 * 8. Controller executes
 *
 * SERVER RESPONDS:
 * ----------------
 * HTTP/1.1 200 OK
 *
 * {
 *   "posts": [...]
 * }
 *
 *
 * EXAMPLE 4: NO TOKEN (PROTECTED ENDPOINT)
 * =========================================
 *
 * CLIENT SENDS:
 * -------------
 * POST /api/v1/posts HTTP/1.1
 * Content-Type: application/json
 * (No Authorization header)
 *
 * {
 *   "title": "My Post"
 * }
 *
 * FILTER EXECUTION:
 * -----------------
 * 1. doFilterInternal() called
 * 2. extractToken() → returns null
 * 3. token != null → false, skip authentication
 * 4. filterChain.doFilter() → continue
 * 5. Spring Security checks: no authentication set
 * 6. SecurityConfig says: .anyRequest().authenticated()
 * 7. POST /posts requires authentication → reject
 *
 * SERVER RESPONDS:
 * ----------------
 * HTTP/1.1 401 Unauthorized
 *
 * {
 *   "status": 401,
 *   "message": "Full authentication is required"
 * }
 *
 *
 * EXAMPLE 5: TAMPERED TOKEN (SECURITY ATTACK)
 * ============================================
 *
 * ATTACKER SENDS:
 * ---------------
 * GET /api/v1/admin/users HTTP/1.1
 * Authorization: Bearer <modified_token>
 *
 * (Attacker changed payload from "user@test.com" to "admin@test.com")
 *
 * FILTER EXECUTION:
 * -----------------
 * 1. doFilterInternal() called
 * 2. extractToken() → returns tampered token
 * 3. token != null → true
 * 4. authenticationService.validateToken():
 *    - Parses JWT
 *    - Recalculates signature with secret key
 *    - Compares: calculated signature != token signature
 *    - Signatures don't match!
 *    - Throws SignatureException
 * 5. catch block: logger.warn("Received invalid auth token")
 * 6. Authentication NOT set
 * 7. Request rejected by Spring Security
 *
 * SERVER RESPONDS:
 * ----------------
 * HTTP/1.1 401 Unauthorized
 *
 * ATTACK BLOCKED! ✓
 *
 *
 * ==========================================
 * ACCESSING AUTHENTICATED USER IN CONTROLLERS
 * ==========================================
 *
 * After this filter sets authentication, you can access current user:
 *
 * METHOD 1: SecurityContextHolder
 * --------------------------------
 * @GetMapping("/profile")
 * public String getProfile() {
 *     Authentication auth = SecurityContextHolder.getContext().getAuthentication();
 *     String username = auth.getName();  // "user@test.com"
 *     return "Profile for: " + username;
 * }
 *
 * METHOD 2: Inject Authentication
 * --------------------------------
 * @GetMapping("/profile")
 * public String getProfile(Authentication authentication) {
 *     String username = authentication.getName();
 *     return "Profile for: " + username;
 * }
 *
 * METHOD 3: @AuthenticationPrincipal
 * -----------------------------------
 * @GetMapping("/profile")
 * public String getProfile(@AuthenticationPrincipal UserDetails userDetails) {
 *     String username = userDetails.getUsername();
 *     return "Profile for: " + username;
 * }
 *
 * METHOD 4: @AuthenticationPrincipal with Custom UserDetails
 * -----------------------------------------------------------
 * @GetMapping("/my-posts")
 * public List<Post> getMyPosts(@AuthenticationPrincipal BlogUserDetails user) {
 *     UUID userId = user.getId();  // From BlogUserDetails
 *     return postService.findByUserId(userId);
 * }
 *
 * METHOD 5: Using Request Attribute (from this filter)
 * -----------------------------------------------------
 * @GetMapping("/my-posts")
 * public List<Post> getMyPosts(HttpServletRequest request) {
 *     UUID userId = (UUID) request.getAttribute("userId");
 *     return postService.findByUserId(userId);
 * }
 *
 *
 * ==========================================
 * SECURITY CONTEXT LIFECYCLE
 * ==========================================
 *
 * IMPORTANT: SecurityContext is REQUEST-SCOPED
 *
 * Request 1: GET /posts (User A)
 * ┌────────────────────────────────┐
 * │ SecurityContext                │
 * │  └─ Authentication             │
 * │      └─ user_a@test.com        │
 * └────────────────────────────────┘
 *
 * Request 2: GET /posts (User B) - Different thread
 * ┌────────────────────────────────┐
 * │ SecurityContext                │
 * │  └─ Authentication             │
 * │      └─ user_b@test.com        │
 * └────────────────────────────────┘
 *
 * Request 3: GET /posts (User A again)
 * ┌────────────────────────────────┐
 * │ SecurityContext                │
 * │  └─ Authentication             │
 * │      └─ user_a@test.com        │
 * └────────────────────────────────┘
 *
 * Each request has its own SecurityContext!
 * User A's context doesn't interfere with User B's context.
 *
 *
 * ==========================================
 * FILTER ORDER IN SPRING SECURITY
 * ==========================================
 *
 * Spring Security Filter Chain (in order):
 * ----------------------------------------
 * 1. SecurityContextPersistenceFilter
 * 2. LogoutFilter
 * 3. JwtAuthenticationFilter ← YOU ARE HERE
 * 4. UsernamePasswordAuthenticationFilter (skipped with JWT)
 * 5. RequestCacheAwareFilter
 * 6. SecurityContextHolderAwareRequestFilter
 * 7. AnonymousAuthenticationFilter
 * 8. SessionManagementFilter
 * 9. ExceptionTranslationFilter
 * 10. FilterSecurityInterceptor (checks authorization)
 * 11. → Controller
 *
 * Your filter runs BEFORE FilterSecurityInterceptor:
 *   ✓ You set authentication
 *   ✓ FilterSecurityInterceptor checks if user has permission
 *   ✓ If authorized → controller executes
 *   ✓ If not authorized → 403 Forbidden
 *
 *
 * ==========================================
 * COMMON ISSUES AND DEBUGGING
 * ==========================================
 *
 * ISSUE 1: "Always getting 401 even with valid token"
 * ----------------------------------------------------
 * Check:
 * □ Authorization header format: "Bearer <token>" (capital B, space)
 * □ Token not expired
 * □ Secret key matches between generation and validation
 * □ SecurityContextHolder.getContext().setAuthentication() is called
 * □ filterChain.doFilter() is called at the end
 *
 * ISSUE 2: "Filter not running at all"
 * ------------------------------------
 * Check:
 * □ Filter registered in SecurityConfig with .addFilterBefore()
 * □ Filter extends OncePerRequestFilter
 * □ Bean is created (@Bean in SecurityConfig)
 *
 * ISSUE 3: "Authentication set but still 401"
 * -------------------------------------------
 * Check:
 * □ Endpoint configuration in SecurityConfig
 * □ User has required roles/authorities
 * □ @PreAuthorize or @Secured annotations match user's roles
 *
 * ISSUE 4: "Request hangs/timeouts"
 * ---------------------------------
 * Cause:
 * □ Forgot filterChain.doFilter() at the end
 * Solution:
 * □ Always call filterChain.doFilter(request, response)
 *
 * ISSUE 5: "Can't access current user in controller"
 * ---------------------------------------------------
 * Check:
 * □ Authentication is set in SecurityContext
 * □ Using correct method to access (@AuthenticationPrincipal)
 * □ UserDetails implementation is correct
 *
 *
 * ==========================================
 * BEST PRACTICES
 * ==========================================
 *
 * ✅ CURRENT IMPLEMENTATION DOES:
 * - Extends OncePerRequestFilter (runs exactly once)
 * - Wraps in try-catch (doesn't crash on errors)
 * - Logs warnings (helps debugging)
 * - Continues chain even on errors (graceful failure)
 * - Validates token properly
 * - Sets authentication in SecurityContext
 * - Stores userId for convenience
 *
 * 🔧 POTENTIAL IMPROVEMENTS:
 * - Add more detailed logging (include username, IP)
 * - Track failed authentication attempts
 * - Add metrics (how many tokens validated per minute)
 * - Cache UserDetails (reduce database queries)
 * - Add token blacklist check
 * - Distinguish between expired vs invalid tokens in logs
 *
 *
 * ==========================================
 * SUMMARY
 * ==========================================
 *
 * THIS FILTER IS THE AUTHENTICATION GATEKEEPER:
 *
 * For EVERY request:
 *   1. Extract token from "Authorization: Bearer <token>" header
 *   2. If token exists → validate and set authentication
 *   3. If no token or invalid → continue without authentication
 *   4. Always call filterChain.doFilter() to continue
 *
 * STEP 3 (from your question) happens here:
 *   SecurityContextHolder.getContext().setAuthentication(authentication)
 *   ↑
 *   This line tells Spring Security: "This user is authenticated!"
 *
 * After this, controllers can access current user via:
 *   - SecurityContextHolder
 *   - @AuthenticationPrincipal
 *   - Authentication parameter
 *   - request.getAttribute("userId")
 */