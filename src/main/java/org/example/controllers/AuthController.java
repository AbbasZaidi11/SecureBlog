package org.example.controllers;

import lombok.RequiredArgsConstructor;
import org.example.dtos.AuthResponse;
import org.example.dtos.LoginRequest;
import org.example.services.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * AUTHENTICATION CONTROLLER
 * =========================
 * PURPOSE: This controller handles user authentication (login) requests.
 *          It's the entry point for users to get their JWT tokens.
 *
 * @RestController:
 *   - Combines @Controller + @ResponseBody
 *
 * @RequestMapping(path = "/api/v1/auth"):
 *
 * @RequiredArgsConstructor (Lombok):
 *   - Automatically generates a constructor for all 'final' fields
 *   - Spring uses this constructor to inject dependencies
 *   - Equivalent to writing:
 *     public AuthController(AuthenticationService authenticationService) {
 *         this.authenticationService = authenticationService;
 *     }
 */
@RestController
@RequestMapping(path = "/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    /**
     * AUTHENTICATION SERVICE DEPENDENCY
     * =================================
     * This service contains the business logic for:
     *   - Authenticating users (verifying email + password)
     *   - Generating JWT tokens
     *
     * WHY 'final'?
     *   - Makes it immutable (can't be changed after construction)
     *   - Required for @RequiredArgsConstructor to work
     *   - Good practice: dependencies shouldn't change during runtime
     *
     * DEPENDENCY INJECTION:
     *   - Spring automatically provides this when creating the controller
     *   - You don't use 'new AuthenticationService()' anywhere
     *   - Spring manages the lifecycle and wiring
     */
    private final AuthenticationService authenticationService;

    /**
     * LOGIN ENDPOINT
     * ==============
     * URL: POST /api/v1/auth
     *
     * PURPOSE: Authenticates a user and returns a JWT token
     *
     * ANNOTATIONS EXPLAINED:
     *
     * ResponseEntity<AuthResponse>:
     *   - Wrapper that lets you control the HTTP response
     *   - You can set: status code, headers, body
     *   - <AuthResponse> means the response body will be an AuthResponse object
     *   - Spring converts AuthResponse → JSON automatically
     *
     * ==================
     * REQUEST FLOW:
     * ==================
     *
     * CLIENT REQUEST:
     * ---------------
     * POST /api/v1/auth
     * Content-Type: application/json
     *
     * {
     *   "email": "user@test.com",
     *   "password": "password"
     * }
     *
     * STEP-BY-STEP EXECUTION:
     * -----------------------
     *
     * 1. Spring receives the HTTP POST request
     * 2. Routes it to this controller based on URL and HTTP method
     * 3. Converts JSON body to LoginRequest object
     * 4. Calls this login() method with the LoginRequest
     * 5. Method executes (see below)
     * 6. Returns ResponseEntity with AuthResponse
     * 7. Spring converts AuthResponse → JSON
     * 8. Sends HTTP response back to client
     *
     * SERVER RESPONSE:
     * ----------------
     * HTTP/1.1 200 OK
     * Content-Type: application/json
     *
     * {
     *   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     *   "expiresIn": 86400
     * }
     */
    @PostMapping
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest loginRequest){

        // ==========================================
        // STEP 1: AUTHENTICATE USER
        // ==========================================
        // Verifies the user's credentials (email + password)
        //
        // WHAT HAPPENS INSIDE authenticate():
        //   a) Creates an authentication token with email + password
        //   b) Calls AuthenticationManager.authenticate()
        //   c) AuthenticationManager uses DaoAuthenticationProvider
        //   d) DaoAuthenticationProvider:
        //      - Calls UserDetailsService to fetch user from DB
        //      - Uses PasswordEncoder to compare passwords
        //   e) If successful: returns UserDetails
        //   f) If failed: throws AuthenticationException (Bad credentials)
        //
        // WHAT IS UserDetails?
        //   - Spring Security's interface for representing a user
        //   - Contains: username, password, authorities (roles/permissions)
        //   - Your User entity likely implements this interface
        //
        // EXCEPTION HANDLING:
        //   - If authentication fails, Spring throws an exception
        //   - Spring's @ControllerAdvice can catch it and return 401 Unauthorized
        //   - No need for try-catch here if you have global exception handling
        UserDetails userDetails = authenticationService.authenticate(
                loginRequest.getEmail(),
                loginRequest.getPassword()
        );

        // ==========================================
        // STEP 2: GENERATE JWT TOKEN
        // ==========================================
        // Creates a JWT token for the authenticated user
        //
        // WHAT HAPPENS INSIDE generateToken():
        //   a) Creates a JWT with claims (username, roles, etc.)
        //   b) Sets expiration time (usually 24 hours = 86400 seconds)
        //   c) Signs the token with a secret key (prevents tampering)
        //   d) Returns the token as a String
        //
        // JWT STRUCTURE (3 parts separated by dots):
        //   Header.Payload.Signature
        //   eyJhbG...  .  eyJzdWI...  .  SflKxw...
        //   ↑            ↑               ↑
        //   Algorithm    User data       Signature (proves authenticity)
        //
        // WHY JWT?
        //   - Stateless: Server doesn't store sessions
        //   - Self-contained: Token contains all user info
        //   - Secure: Signature prevents tampering
        //   - Portable: Works across different servers/services
        String tokenValue = authenticationService.generateToken(userDetails);

        // ==========================================
        // STEP 3: BUILD RESPONSE
        // ==========================================
        // Creates the response object to send back to the client
        //
        // AuthResponse contains:
        //   - token: The JWT string the client will use for future requests
        //   - expiresIn: How long the token is valid (in seconds)
        //
        // 86400 seconds = 24 hours
        //   - After this time, token expires
        //   - Client must login again to get a new token
        //   - Prevents stolen tokens from being valid forever
        //
        // .builder() pattern (Lombok):
        //   - Fluent way to create objects
        //   - More readable than: new AuthResponse(token, 86400)
        AuthResponse authResponse = AuthResponse.builder()
                .token(tokenValue)
                .expiresIn(86400)  // Token valid for 24 hours
                .build();

        // ==========================================
        // STEP 4: RETURN RESPONSE
        // ==========================================
        // ResponseEntity.ok() creates a response with:
        //   - HTTP Status: 200 OK
        //   - Body: AuthResponse object (converted to JSON)
        //
        // Alternative status codes you could use:
        //   - ResponseEntity.status(HttpStatus.CREATED).body(authResponse)
        //   - ResponseEntity.status(201).body(authResponse)
        //
        // Spring automatically serializes authResponse to JSON:
        //   { "token": "eyJ...", "expiresIn": 86400 }
        return ResponseEntity.ok(authResponse);
    }
}

/**
 * ==========================================
 * COMPLETE AUTHENTICATION FLOW EXAMPLE
 * ==========================================
 *
 * SCENARIO: User wants to login
 *
 * CLIENT SIDE (JavaScript example):
 * ----------------------------------
 * fetch('http://localhost:8080/api/v1/auth', {
 *   method: 'POST',
 *   headers: {
 *     'Content-Type': 'application/json'
 *   },
 *   body: JSON.stringify({
 *     email: 'user@test.com',
 *     password: 'password'
 *   })
 * })
 * .then(response => response.json())
 * .then(data => {
 *   // Store token for future requests
 *   localStorage.setItem('token', data.token);
 *   console.log('Login successful! Token expires in:', data.expiresIn, 'seconds');
 * })
 * .catch(error => {
 *   console.error('Login failed:', error);
 * });
 *
 *
 * SERVER SIDE (This Controller):
 * -------------------------------
 * 1. Request arrives: POST /api/v1/auth
 *    Body: { "email": "user@test.com", "password": "password" }
 *
 * 2. Spring routes to login() method
 *    - Converts JSON → LoginRequest object
 *
 * 3. authenticationService.authenticate() is called
 *    - Validates email exists in database
 *    - Compares password hash
 *    - Returns UserDetails if valid
 *    - Throws exception if invalid
 *
 * 4. authenticationService.generateToken() is called
 *    - Creates JWT with user info
 *    - Signs it with secret key
 *    - Returns token string
 *
 * 5. AuthResponse is built
 *    - Contains token and expiration time
 *
 * 6. Response sent back to client
 *    Status: 200 OK
 *    Body: { "token": "eyJ...", "expiresIn": 86400 }
 *
 *
 * CLIENT RECEIVES RESPONSE:
 * -------------------------
 * The client now has a token! For subsequent requests:
 *
 * fetch('http://localhost:8080/api/v1/posts', {
 *   method: 'POST',
 *   headers: {
 *     'Content-Type': 'application/json',
 *     'Authorization': 'Bearer eyJ...'  // ← Token from login
 *   },
 *   body: JSON.stringify({
 *     title: 'My Post',
 *     content: 'Post content...'
 *   })
 * });
 *
 * The JwtAuthenticationFilter will:
 *   - Extract the token from Authorization header
 *   - Validate it
 *   - Load user details
 *   - Allow the request to proceed
 *
 *
 * ERROR SCENARIOS:
 * ================
 *
 * 1. WRONG PASSWORD:
 *    - authenticationService.authenticate() throws BadCredentialsException
 *    - Global exception handler catches it
 *    - Returns: 401 Unauthorized
 *    - Body: { "error": "Invalid credentials" }
 *
 * 2. USER NOT FOUND:
 *    - UserDetailsService throws UsernameNotFoundException
 *    - Returns: 401 Unauthorized
 *    - Body: { "error": "User not found" }
 *
 * 3. MISSING FIELDS:
 *    - Spring validation (if configured) rejects request
 *    - Returns: 400 Bad Request
 *    - Body: { "error": "Email and password are required" }
 *
 * 4. TOKEN GENERATION FAILS:
 *    - authenticationService.generateToken() throws exception
 *    - Returns: 500 Internal Server Error
 *    - Body: { "error": "Could not generate token" }
 *
 *
 * DATA TRANSFER OBJECTS (DTOs):
 * =============================
 *
 * LoginRequest (Input DTO):
 * -------------------------
 * class LoginRequest {
 *     private String email;
 *     private String password;
 *     // getters and setters
 * }
 *
 * Purpose:
 *   - Represents the incoming login data
 *   - Separates API contract from internal User entity
 *   - Can add validation annotations: @NotBlank, @Email, etc.
 *
 *
 * AuthResponse (Output DTO):
 * --------------------------
 * class AuthResponse {
 *     private String token;
 *     private long expiresIn;
 *     // getters, builder, etc.
 * }
 *
 * Purpose:
 *   - Represents the outgoing response
 *   - Only exposes what client needs (not entire User object)
 *   - Can add additional fields: refreshToken, userRole, etc.
 *
 *
 * SECURITY BEST PRACTICES:
 * ========================
 *
 * ✅ CURRENT IMPLEMENTATION DOES:
 *   - Uses POST (not GET) for login
 *   - Sends password in request body (not URL)
 *   - Returns token instead of storing session
 *   - Sets token expiration
 *
 * 🔒 ADDITIONAL RECOMMENDATIONS:
 *   - Use HTTPS in production (encrypts data in transit)
 *   - Implement rate limiting (prevent brute force attacks)
 *   - Add refresh tokens (for extending sessions without re-login)
 *   - Log failed login attempts
 *   - Consider 2FA for sensitive applications
 *   - Add account lockout after multiple failed attempts
 *   - Sanitize error messages (don't reveal if user exists)
 *
 *
 * TESTING THIS ENDPOINT:
 * ======================
 *
 * Using curl:
 * -----------
 * curl -X POST http://localhost:8080/api/v1/auth \
 *   -H "Content-Type: application/json" \
 *   -d '{"email":"user@test.com","password":"password"}'
 *
 * Using Postman:
 * --------------
 * POST http://localhost:8080/api/v1/auth
 * Headers: Content-Type: application/json
 * Body (raw JSON):
 * {
 *   "email": "user@test.com",
 *   "password": "password"
 * }
 *
 * Expected Response:
 * ------------------
 * {
 *   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQHRlc3QuY29tIiwiaWF0IjoxNjMwNDYwODAwLCJleHAiOjE2MzA1NDcyMDB9.xyz123...",
 *   "expiresIn": 86400
 * }
 *
 *
 * WHAT HAPPENS AFTER LOGIN:
 * =========================
 *
 * 1. Client stores the token (localStorage, sessionStorage, or memory)
 * 2. For every protected API request, client includes:
 *    Header: Authorization: Bearer <token>
 * 3. JwtAuthenticationFilter validates the token
 * 4. If valid, request proceeds
 * 5. If invalid/expired, returns 401 Unauthorized
 * 6. Client handles 401 by redirecting to login page
 *
 * Token Lifecycle:
 * ----------------
 * Login → Receive Token → Use Token (24h) → Token Expires → Login Again
 *         └─────────────┬────────────────┘
 *                  Valid Period
 */