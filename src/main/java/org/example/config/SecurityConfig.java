package org.example.config;

import org.example.repositories.UserRepository;
import org.example.security.BlogUserDetailsService;
import org.example.security.JwtAuthenticationFilter;
import org.example.services.AuthenticationService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * SECURITY CONFIGURATION CLASS
 * ============================
 * This is the HEART of your application's security setup.
 * Think of it as the "security blueprint" that tells Spring:
 *   - Who can access what endpoints
 *   - How to verify passwords
 *   - How to validate JWT tokens
 *   - Where to find user information
 *
 * @Configuration tells Spring: "Scan this class and register all @Bean methods"
 */
@Configuration
public class SecurityConfig {

    /**
     * JWT AUTHENTICATION FILTER BEAN
     * ===============================
     * PURPOSE: This is a custom filter that intercepts EVERY incoming HTTP request
     *          BEFORE it reaches your controllers.
     *
     * WHAT IT DOES:
     *   1. Checks if the request has an "Authorization" header
     *   2. Extracts the JWT token from header (format: "Bearer <token>")
     *   3. Validates the token (checks signature, expiration, etc.)
     *   4. If valid → extracts username → loads user details → sets authentication in SecurityContext
     *   5. If invalid/missing → rejects the request (returns 401/403)
     *
     * THINK OF IT AS: A security guard at the entrance who checks everyone's ID badge
     *                 before letting them into the building.
     *
     * FLOW: Request → JwtAuthenticationFilter → (if valid) → Controller
     *                                        → (if invalid) → Rejected
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(AuthenticationService authenticationService) {
        return new JwtAuthenticationFilter(authenticationService);
    }

    /**
     * PASSWORD ENCODER BEAN
     * =====================
     * PURPOSE: Handles password encryption/hashing for security.
     *
     * WHY WE NEED IT:
     *   - NEVER store passwords in plain text in your database
     *   - If your DB is hacked, passwords should be unreadable
     *
     * WHAT IT DOES:
     *   - When user registers → encodes "password123" → stores "{bcrypt}$2a$10$XYZ..." in DB
     *   - When user logs in → takes input password → encodes it → compares with DB hash
     *
     * DELEGATING ENCODER:
     *   - Supports multiple algorithms (bcrypt, pbkdf2, scrypt, etc.)
     *   - Format: "{algorithm}hashedPassword"
     *   - Default is bcrypt (industry standard, very secure)
     *
     * EXAMPLE:
     *   Input: "myPassword"
     *   Encoded: "{bcrypt}$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * DAO AUTHENTICATION PROVIDER BEAN
     * ================================
     * PURPOSE: This is the "authentication engine" that verifies user credentials.
     *
     * WHAT IS DAO?
     *   - DAO = Data Access Object
     *   - It means this provider fetches user data from your database
     *
     * HOW IT WORKS (Login Flow):
     *   1. User submits email + password
     *   2. Spring calls this provider's authenticate() method
     *   3. Provider uses UserDetailsService to fetch user from DB by email
     *   4. Provider uses PasswordEncoder to compare submitted password with stored hash
     *   5. If match → authentication successful → user logged in
     *   6. If no match → authentication fails → throws exception
     *
     * ANALOGY: Like a librarian who:
     *   - Looks up your library card (UserDetailsService)
     *   - Checks if your PIN matches (PasswordEncoder)
     *   - Either grants or denies access
     *
     * YOU DON'T MANUALLY USE THIS: Spring Security automatically calls it during login
     */
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService uds, PasswordEncoder pe) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(uds);  // Where to find users
        provider.setPasswordEncoder(pe);      // How to verify passwords
        return provider;
    }

    /**
     * USER DETAILS SERVICE BEAN
     * =========================
     * PURPOSE: This tells Spring "HOW to fetch user information from YOUR database"
     *
     * SPRING'S QUESTION: "When someone tries to login with email 'user@test.com',
     *                     where do I find that user?"
     * YOUR ANSWER: "Use my BlogUserDetailsService which queries my UserRepository"
     *
     * WHAT HAPPENS:
     *   - BlogUserDetailsService implements Spring's UserDetailsService interface
     *   - It has a method: loadUserByUsername(String email)
     *   - This method queries your UserRepository
     *   - Returns a UserDetails object (Spring's representation of a user)
     *
     * TEST USER CREATION:
     *   - This code creates a default test user if it doesn't exist
     *   - Email: user@test.com
     *   - Password: password (encoded as bcrypt hash)
     *   - Useful for development/testing without manual user creation
     *
     * IMPORTANT: UserDetailsService is the BRIDGE between Spring Security
     *            and your custom User entity/database
     */
    @Bean
    public UserDetailsService userDetailsService (UserRepository userRepository){
        // Create your custom implementation that knows how to fetch users from DB
        BlogUserDetailsService blogUserDetailsService = new BlogUserDetailsService(userRepository);



        // TEST USER SETUP (for development convenience)
        String email = "user@test.com";
        userRepository.findByEmail(email).orElseGet(() -> {
            // Create a new user using YOUR User entity (not Spring's)
            org.example.entities.User newUser = org.example.entities.User.builder()
                    .name("Test User")
                    .email(email)
                    .password(passwordEncoder().encode("password"))  // Encode the password!
                    .build();
            return userRepository.save(newUser);  // Save to database
        });

        return blogUserDetailsService;
    }

    /**
     * SECURITY FILTER CHAIN BEAN
     * ==========================
     * PURPOSE: This is the MAIN security configuration. It defines:
     *   - Which endpoints are public (no login needed)
     *   - Which endpoints require authentication
     *   - How authentication works (JWT vs sessions)
     *   - What security features are enabled/disabled
     *
     * THINK OF IT AS: The complete security rulebook for your application
     *
     * CONFIGURATION BREAKDOWN:
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtAuthenticationFilter jwtAuthenticationFilter,
                                                   DaoAuthenticationProvider daoAuthenticationProvider) throws Exception {

        // STEP 1: Plug in the AUTHENTICATION mechanism for username+password logins.
        // This is used when you explicitly call AuthenticationManager.authenticate(...)
        // (usually in your /auth/login flow). It relies on your UserDetailsService + PasswordEncoder.
        http.authenticationProvider(daoAuthenticationProvider)

                // STEP 2: AUTHORIZATION rules — who can call which endpoints.
                // These are evaluated IN THE ORDER THEY ARE DECLARED (first match wins).
                // Keep more specific patterns (like /posts/drafts) BEFORE broader ones (/posts/**).
                .authorizeHttpRequests(auth -> auth
                        // ---- PUBLIC ENDPOINTS (no JWT needed) ----
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/login").permitAll()

                        // IMPORTANT: This comes BEFORE "/api/v1/posts/**" so that drafts stay protected.
                        .requestMatchers(HttpMethod.GET, "/api/v1/posts/drafts").authenticated()

                        // Public reads for posts/categories/tags (customize as needed)
                        .requestMatchers(HttpMethod.GET, "/api/v1/posts/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/categories/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/tags/**").permitAll()

                        // ---- EVERYTHING ELSE requires authentication (JWT must be valid) ----
                        .anyRequest().authenticated()
                )

                // STEP 3: Disable CSRF because this API is stateless and uses Authorization headers (JWT),
                // not cookie-based sessions. With JWT, the usual CSRF attack vector (cookies) doesn’t apply.
                .csrf(csrf -> csrf.disable())

                // STEP 4: Tell Spring Security we are STATELESS.
                // No HttpSession will be created or used; every request must carry a valid JWT.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // STEP 5: Insert your JWT filter into the filter chain.
                // It must run BEFORE UsernamePasswordAuthenticationFilter so that requests with a valid
                // JWT are authenticated early (SecurityContext is set) before controller methods run.
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        // Build the immutable SecurityFilterChain object that Spring will use for incoming requests.
        return http.build();
    }

    /**
     * AUTHENTICATION MANAGER BEAN
     * ===========================
     * PURPOSE: This is the "entry point" for authentication in Spring Security
     *
     * WHAT IT DOES:
     *   - Coordinates all authentication providers (like DaoAuthenticationProvider)
     *   - When you call authenticate() in your code, it goes through this manager
     *   - The manager tries each registered provider until one succeeds
     *
     * WHERE IT'S USED:
     *   - In your AuthenticationService during login
     *   - Example: authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password))
     *
     * SIMPLE EXPLANATION:
     *   - Without this bean, you couldn't inject AuthenticationManager into your services
     *   - This exposes Spring's internal authentication manager as a bean
     *   - Now you can use it in your custom login logic
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}

/**
 * ==========================================
 * COMPLETE AUTHENTICATION FLOW EXAMPLES
 * ==========================================
 *
 * SCENARIO 1: USER LOGIN (POST /api/v1/auth)
 * ===========================================
 * Step 1: User sends request
 *    POST /api/v1/auth
 *    Body: { "email": "user@test.com", "password": "password" }
 *
 * Step 2: Request reaches your AuthController
 *    → Calls authenticationService.authenticate(email, password)
 *
 * Step 3: Inside AuthenticationService
 *    → Creates UsernamePasswordAuthenticationToken
 *    → Calls authenticationManager.authenticate(token)
 *
 * Step 4: AuthenticationManager delegates to DaoAuthenticationProvider
 *    → Provider calls BlogUserDetailsService.loadUserByUsername(email)
 *    → BlogUserDetailsService queries UserRepository
 *    → Returns User from database
 *
 * Step 5: DaoAuthenticationProvider verifies password
 *    → Uses PasswordEncoder.matches(rawPassword, encodedPassword)
 *    → Compares "password" with "{bcrypt}$2a$10$..."
 *
 * Step 6: If password matches
 *    → Authentication successful
 *    → Generate JWT token
 *    → Return token to client
 *    Response: { "token": "eyJhbGciOiJIUzI1NiIs..." }
 *
 * Step 7: If password doesn't match
 *    → Throw BadCredentialsException
 *    → Return 401 Unauthorized
 *
 *
 * SCENARIO 2: ACCESSING PROTECTED ENDPOINT (GET /api/v1/posts/private)
 * =====================================================================
 * Step 1: User sends request with JWT token
 *    GET /api/v1/posts/private
 *    Headers: { "Authorization": "Bearer eyJhbGciOiJIUzI1NiIs..." }
 *
 * Step 2: JwtAuthenticationFilter intercepts request
 *    → Extracts token from "Authorization" header
 *    → Validates token signature and expiration
 *
 * Step 3: If token is valid
 *    → Extract username from token
 *    → Load user details via BlogUserDetailsService
 *    → Create Authentication object
 *    → Set authentication in SecurityContext
 *
 * Step 4: Request proceeds to controller
 *    → Spring knows user is authenticated
 *    → Controller method executes
 *    → Response returned: { "data": "..." }
 *
 * Step 5: If token is invalid/missing
 *    → JwtAuthenticationFilter rejects request
 *    → Return 401/403
 *    → Controller never reached
 *
 *
 * SCENARIO 3: ACCESSING PUBLIC ENDPOINT (GET /api/v1/posts)
 * ==========================================================
 * Step 1: User sends request (no token needed)
 *    GET /api/v1/posts
 *
 * Step 2: JwtAuthenticationFilter runs
 *    → Notices no token (that's okay for public endpoints)
 *    → Doesn't set authentication
 *    → Lets request through
 *
 * Step 3: SecurityFilterChain checks authorization rules
 *    → Sees GET /api/v1/posts/** is permitAll()
 *    → Allows request without authentication
 *
 * Step 4: Controller executes and returns data
 *    → Response: { "posts": [...] }
 *
 *
 * KEY CONCEPTS SUMMARY
 * ====================
 *
 * 1. FILTER CHAIN: Request → JwtFilter → Spring Filters → Controller
 *
 * 2. BEANS AND THEIR ROLES:
 *    - JwtAuthenticationFilter: Validates JWT tokens on each request
 *    - PasswordEncoder: Hashes and verifies passwords
 *    - UserDetailsService: Fetches users from database
 *    - DaoAuthenticationProvider: Verifies credentials during login
 *    - AuthenticationManager: Coordinates authentication process
 *    - SecurityFilterChain: Defines access rules and security config
 *
 * 3. STATELESS AUTHENTICATION:
 *    - No sessions stored on server
 *    - Each request must include JWT token
 *    - Token contains all necessary user info
 *    - Server just validates token signature
 *
 * 4. PUBLIC vs PROTECTED ENDPOINTS:
 *    - Public: .permitAll() - no authentication needed
 *    - Protected: .authenticated() - must have valid JWT token
 *
 * 5. PASSWORD SECURITY:
 *    - Never store plain text passwords
 *    - Always use PasswordEncoder
 *    - BCrypt is industry standard (slow = good for passwords)
 *
 * DEBUGGING TIPS:
 * ===============
 * - If login fails: Check DaoAuthenticationProvider and PasswordEncoder
 * - If token validation fails: Check JwtAuthenticationFilter logic
 * - If 403 Forbidden: Check SecurityFilterChain's authorization rules
 * - If 401 Unauthorized: Check if JWT token is present and valid
 */