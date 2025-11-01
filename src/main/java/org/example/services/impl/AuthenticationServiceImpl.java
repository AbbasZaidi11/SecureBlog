package org.example.services.impl;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.example.services.AuthenticationService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * AUTHENTICATION SERVICE IMPLEMENTATION
 * =====================================
 * PURPOSE: This is the "brain" of your authentication system.
 *          It handles three main responsibilities:
 *          1. Authenticating users (verifying credentials)
 *          2. Generating JWT tokens (creating access tokens)
 *          3. Validating JWT tokens (verifying tokens on each request)
 *
 * WHAT IS JWT (JSON Web Token)?
 * =============================
 * A JWT is a self-contained token that proves a user's identity.
 *
 * Structure: xxxxx.yyyyy.zzzzz (three parts separated by dots)
 *
 * 1. HEADER (xxxxx):
 *    { "alg": "HS256", "typ": "JWT" }
 *    - Algorithm used for signing
 *    - Type of token
 *
 * 2. PAYLOAD (yyyyy):
 *    { "sub": "user@test.com", "iat": 1635000000, "exp": 1635086400 }
 *    - Subject (username/email)
 *    - Issued at timestamp
 *    - Expiration timestamp
 *    - Any custom claims you add
 *
 * 3. SIGNATURE (zzzzz):
 *    HMACSHA256(base64(header) + "." + base64(payload), secret)
 *    - Proves the token wasn't tampered with
 *    - Created using your secret key
 *    - Can't be forged without the secret
 *
 * WHY JWT?
 * --------
 * ✓ Stateless: Server doesn't store session data
 * ✓ Self-contained: Token has all user info
 * ✓ Scalable: Works across multiple servers
 * ✓ Cross-domain: Can be used in mobile apps, different domains
 * ✓ Secure: Signature prevents tampering
 *
 * ANNOTATIONS EXPLAINED:
 *
 * @Service:
 *   - Marks this as a business logic component
 *   - Spring creates a single instance (singleton)
 *   - Can be injected into controllers
 *
 * @RequiredArgsConstructor (Lombok):
 *   - Auto-generates constructor for 'final' fields
 *   - Spring uses this to inject dependencies
 */
@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    /**
     * DEPENDENCY: AUTHENTICATION MANAGER
     * ==================================
     * The "coordinator" for authentication in Spring Security.
     *
     * WHAT IT DOES:
     *   - Takes credentials (email + password)
     *   - Delegates to authentication providers (like DaoAuthenticationProvider)
     *   - Returns authenticated user or throws exception
     *
     * WHERE IT'S CONFIGURED:
     *   - In SecurityConfig.authenticationManager() bean
     *
     * WHEN IT'S USED:
     *   - During login in the authenticate() method below
     */
    private final AuthenticationManager authenticationManager;

    /**
     * DEPENDENCY: USER DETAILS SERVICE
     * ================================
     * Your custom service that loads users from the database.
     *
     * WHAT IT DOES:
     *   - Fetches user by username/email
     *   - Returns UserDetails (Spring Security's user representation)
     *
     * WHERE IT'S CONFIGURED:
     *   - In SecurityConfig.userDetailsService() bean
     *   - Your BlogUserDetailsService implements this interface
     *
     * WHEN IT'S USED:
     *   - After successful authentication to get full user details
     *   - When validating tokens to get user information
     */
    private final UserDetailsService userDetailsService;

    /**
     * JWT SECRET KEY
     * ==============
     * The "password" used to sign and verify JWT tokens.
     *
     * @Value("${jwt.secret}"):
     *   - Injects value from application.properties or application.yml
     *   - Example in application.properties:
     *     jwt.secret=mySecretKeyForJwtTokenSigningMustBeLongEnough
     *
     * SECURITY CRITICAL:
     * ------------------
     * ⚠️ NEVER commit this to Git!
     * ⚠️ Use environment variables in production!
     * ⚠️ Must be at least 256 bits (32 characters) for HS256
     *
     * HOW IT WORKS:
     *   - Used to create signature when generating tokens
     *   - Used to verify signature when validating tokens
     *   - Anyone with this key can create valid tokens!
     *
     * PRODUCTION SETUP:
     * -----------------
     * Instead of application.properties:
     *   - Use environment variable: JWT_SECRET=your-secret-here
     *   - Or use vault services: AWS Secrets Manager, HashiCorp Vault
     *   - Rotate regularly (change every few months)
     *
     * Example application.yml:
     * ------------------------
     * jwt:
     *   secret: ${JWT_SECRET:defaultSecretForDevelopmentOnlyDoNotUseInProduction}
     */
    @Value("${jwt.secret}")
    private String secretKey;

    /**
     * JWT EXPIRATION TIME
     * ===================
     * How long tokens remain valid (in milliseconds).
     *
     * 86400000L = 86,400,000 milliseconds
     *           = 86,400 seconds
     *           = 1,440 minutes
     *           = 24 hours
     *
     * WHY 24 HOURS?
     *   - Common default for web applications
     *   - Balance between security and user experience
     *   - Too short: users constantly re-login (annoying)
     *   - Too long: stolen tokens valid longer (security risk)
     *
     * DIFFERENT USE CASES:
     *   - Banking apps: 15-30 minutes (high security)
     *   - Social media: 7-30 days (convenience)
     *   - Internal tools: 8 hours (work day)
     *   - APIs: 1 hour with refresh tokens
     *
     * BEST PRACTICE:
     *   - Use shorter expiry + refresh tokens
     *   - Access token: 15 minutes (for API calls)
     *   - Refresh token: 7 days (to get new access token)
     *
     * MAKING IT CONFIGURABLE:
     * -----------------------
     * @Value("${jwt.expiry:86400000}")
     * private Long jwtExpiryMs;
     *
     * Then in application.properties:
     * jwt.expiry=3600000  # 1 hour
     */
    private final Long jwtExpiryMs = 86400000L;

    /**
     * AUTHENTICATE USER METHOD
     * ========================
     * PURPOSE: Verifies user credentials (email + password).
     *          This is called during LOGIN.
     *
     * PARAMETERS:
     *   @param email - User's email address (used as username)
     *   @param password - Plain text password (NOT hashed yet)
     *
     * RETURNS:
     *   UserDetails - Spring Security's representation of the user
     *                 Contains: username, password, authorities (roles)
     *
     * THROWS:
     *   BadCredentialsException - If password is wrong or user not found
     *
     * ==========================================
     * EXECUTION FLOW:
     * ==========================================
     *
     * CLIENT REQUEST:
     * ---------------
     * POST /api/v1/auth
     * { "email": "user@test.com", "password": "password123" }
     *
     * STEP-BY-STEP PROCESS:
     * ---------------------
     * 1. AuthController calls this method
     * 2. Method executes (see steps below)
     * 3. Returns UserDetails if successful
     * 4. Controller uses UserDetails to generate JWT
     * 5. Client receives token and uses it for future requests
     */
    @Override
    public UserDetails authenticate(String email, String password) {

        // STEP 1: Attempt to authenticate the user
        // =========================================
        // Creates an "authentication token" (NOT a JWT, confusing name!)
        // This is Spring Security's way of representing login credentials
        //
        // UsernamePasswordAuthenticationToken contains:
        //   - Principal: email (the username)
        //   - Credentials: password (plain text)
        //   - Authenticated: false (not verified yet)
        //
        // authenticationManager.authenticate() does:
        //   a) Calls DaoAuthenticationProvider (configured in SecurityConfig)
        //   b) DaoAuthenticationProvider calls UserDetailsService.loadUserByUsername(email)
        //   c) Loads user from database via BlogUserDetailsService
        //   d) Compares submitted password with stored hash using PasswordEncoder
        //   e) If match: authentication succeeds
        //   f) If no match: throws BadCredentialsException
        //
        // WHAT PASSWORDENCODER DOES:
        // --------------------------
        // Submitted: "password123" (plain text)
        // Stored: "{bcrypt}$2a$10$XYZ..." (hashed)
        //
        // Process:
        //   1. Extract algorithm from stored password: bcrypt
        //   2. Hash submitted password with same algorithm
        //   3. Compare hashes (NOT plain text!)
        //   4. Match → success, No match → exception
        //
        // WHY THIS IS SECURE:
        // -------------------
        // ✓ Password never stored in plain text
        // ✓ Can't reverse the hash to get original password
        // ✓ Same password creates different hashes (salt)
        // ✓ Slow algorithm (bcrypt) prevents brute force
        //
        // EXCEPTION HANDLING:
        // -------------------
        // If authentication fails, this line throws BadCredentialsException
        // ErrorController.handleBadCredentialsException() catches it
        // Returns 401 Unauthorized to client
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, password)
        );

        // STEP 2: Load full user details
        // ===============================
        // If we reach here, authentication succeeded!
        // Now we load the complete user details from database
        //
        // WHY LOAD AGAIN?
        //   - authenticationManager.authenticate() only verifies credentials
        //   - It doesn't return the UserDetails object
        //   - We need UserDetails to create JWT token
        //   - UserDetails contains: username, roles, enabled status, etc.
        //
        // userDetailsService.loadUserByUsername() does:
        //   a) Queries database: SELECT * FROM users WHERE email = ?
        //   b) Wraps result in UserDetails implementation
        //   c) Returns user with all properties
        //
        // OPTIMIZATION NOTE:
        // ------------------
        // This means we query the database twice:
        //   1. During authentication (to get password hash)
        //   2. Here (to get full user details)
        //
        // Could be optimized by storing UserDetails during authentication,
        // but this approach is simpler and more maintainable.
        return userDetailsService.loadUserByUsername(email);
    }

    /**
     * GENERATE JWT TOKEN METHOD
     * =========================
     * PURPOSE: Creates a signed JWT token for an authenticated user.
     *          This is called AFTER successful login.
     *
     * PARAMETERS:
     *   @param userDetails - The authenticated user's details
     *
     * RETURNS:
     *   String - The JWT token (format: xxxxx.yyyyy.zzzzz)
     *
     * TOKEN STRUCTURE:
     * ----------------
     * eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9           ← Header (algorithm & type)
     * .
     * eyJzdWIiOiJ1c2VyQHRlc3QuY29tIiwiaWF0Ijox...   ← Payload (user data & timestamps)
     * .
     * SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c    ← Signature (proves authenticity)
     *
     * ==========================================
     * EXECUTION FLOW:
     * ==========================================
     *
     * WHEN IT'S CALLED:
     * -----------------
     * After authenticate() succeeds in AuthController:
     *
     * UserDetails user = authenticationService.authenticate(email, password);
     * String token = authenticationService.generateToken(user);  ← HERE
     * return ResponseEntity.ok(new AuthResponse(token, 86400));
     */
    @Override
    public String generateToken(UserDetails userDetails) {

        // STEP 1: Create claims (token payload data)
        // ==========================================
        // Claims are key-value pairs stored in the token
        //
        // STANDARD CLAIMS (automatically added by Jwts.builder()):
        //   - sub (subject): username/email
        //   - iat (issued at): when token was created
        //   - exp (expiration): when token expires
        //
        // CUSTOM CLAIMS (you can add in this map):
        //   - roles: ["ADMIN", "USER"]
        //   - userId: 123
        //   - permissions: ["READ", "WRITE"]
        //   - any other data you need
        //
        // EXAMPLE WITH CUSTOM CLAIMS:
        // ---------------------------
        // Map<String, Object> claims = new HashMap<>();
        // claims.put("roles", userDetails.getAuthorities());
        // claims.put("userId", ((User) userDetails).getId());
        //
        // WHY EMPTY HERE?
        //   - Basic implementation only needs username (added via setSubject)
        //   - Keeps token size small
        //   - Can add roles/permissions later when needed
        Map<String, Object> claims = new HashMap<>();

        // STEP 2: Build and sign the JWT token
        // =====================================
        // Jwts.builder() provides a fluent API for creating tokens
        return Jwts.builder()

                // Set custom claims (if any)
                // --------------------------
                // Adds all key-value pairs from the map to token payload
                // Must be called BEFORE setSubject/setIssuedAt/setExpiration
                // (Otherwise standard claims would overwrite these)
                .setClaims(claims)

                // Set subject (username/email)
                // ----------------------------
                // "sub" claim: identifies who the token is about
                // Standard JWT claim
                // Usually username or email
                //
                // Result in token:
                // { "sub": "user@test.com" }
                .setSubject(userDetails.getUsername())

                // Set issued at timestamp
                // -----------------------
                // "iat" claim: when token was created
                // Standard JWT claim
                // Used to track token age
                //
                // System.currentTimeMillis() = current time in milliseconds since Jan 1, 1970
                // new Date() converts to Date object
                //
                // Result in token:
                // { "iat": 1635000000 }
                .setIssuedAt(new Date(System.currentTimeMillis()))

                // Set expiration timestamp
                // ------------------------
                // "exp" claim: when token expires
                // Standard JWT claim
                // After this time, token is invalid
                //
                // Current time + 86400000ms (24 hours)
                //
                // Example:
                //   Current: 2024-10-29 10:00:00
                //   Expires: 2024-10-30 10:00:00
                //
                // Result in token:
                // { "exp": 1635086400 }
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiryMs))

                // Sign the token with secret key
                // -------------------------------
                // Creates the signature (third part of JWT)
                //
                // getSigningKey(): Converts secret string → cryptographic Key
                // SignatureAlgorithm.HS256: HMAC-SHA256 algorithm
                //
                // WHAT IS HMAC-SHA256?
                //   - Symmetric algorithm (same key for signing & verifying)
                //   - Fast and secure
                //   - Produces 256-bit signature
                //   - Industry standard for JWTs
                //
                // THE SIGNATURE PROVES:
                //   1. Token was created by someone with the secret key (authenticity)
                //   2. Token hasn't been modified after creation (integrity)
                //   3. Token is trustworthy
                //
                // HOW SIGNATURE IS CREATED:
                // -------------------------
                // signature = HMAC-SHA256(
                //     base64(header) + "." + base64(payload),
                //     secretKey
                // )
                //
                // If someone changes payload (e.g., changes email):
                //   - Signature won't match anymore
                //   - Token validation will fail
                //   - Can't forge tokens without the secret!
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)

                // Build and return the token string
                // ---------------------------------
                // .compact() does:
                //   1. Base64 encodes header
                //   2. Base64 encodes payload
                //   3. Creates signature
                //   4. Combines: header.payload.signature
                //   5. Returns as string
                //
                // Result: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI..."
                .compact();
    }

    /**
     * VALIDATE TOKEN METHOD
     * =====================
     * PURPOSE: Verifies a JWT token and extracts user information.
     *          This is called on EVERY request to protected endpoints.
     *
     * PARAMETERS:
     *   @param token - JWT token from Authorization header
     *
     * RETURNS:
     *   UserDetails - User information if token is valid
     *
     * THROWS:
     *   JwtException - If token is invalid, expired, or tampered with
     *
     * ==========================================
     * EXECUTION FLOW:
     * ==========================================
     *
     * WHEN IT'S CALLED:
     * -----------------
     * On every request to protected endpoints:
     *
     * CLIENT REQUEST:
     * ---------------
     * GET /api/v1/posts
     * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
     *
     * FILTER CHAIN:
     * -------------
     * 1. JwtAuthenticationFilter extracts token from header
     * 2. Calls this method: validateToken(token)  ← HERE
     * 3. If valid: sets authentication in SecurityContext
     * 4. If invalid: throws exception (401 Unauthorized)
     * 5. Request proceeds to controller (or gets rejected)
     *
     * VALIDATION CHECKS:
     * ------------------
     * ✓ Token format is correct (header.payload.signature)
     * ✓ Signature is valid (proves token wasn't tampered)
     * ✓ Token hasn't expired (checks "exp" claim)
     * ✓ Token was issued by us (verified via signature)
     * ✓ User still exists in database
     */
    @Override
    public UserDetails validateToken(String token) {

        // STEP 1: Extract username from token
        // ====================================
        // extractUsername(token) does:
        //   a) Parses the JWT token
        //   b) Verifies signature (proves token is authentic)
        //   c) Checks expiration (throws exception if expired)
        //   d) Extracts "sub" claim (username/email)
        //   e) Returns username
        //
        // WHAT HAPPENS IF TOKEN IS INVALID?
        //   - Expired token → ExpiredJwtException
        //   - Tampered token → SignatureException
        //   - Malformed token → MalformedJwtException
        //   - Any JWT exception → caught by filter, returns 401
        String username = extractUsername(token);

        // STEP 2: Load user details from database
        // ========================================
        // Why load from database instead of trusting token?
        //
        // SECURITY REASONS:
        //   1. User might have been deleted after token was issued
        //   2. User might have been disabled/banned
        //   3. User roles might have changed
        //   4. Password might have been changed (should invalidate tokens)
        //
        // TRADE-OFF:
        //   - Con: Database query on every request (performance hit)
        //   - Pro: Always up-to-date user information
        //   - Pro: Can immediately revoke access by deleting user
        //
        // OPTIMIZATION OPTIONS:
        //   - Cache UserDetails (Redis, in-memory cache)
        //   - Store roles in token to avoid DB lookup
        //   - Use refresh tokens with short-lived access tokens
        //
        // userDetailsService.loadUserByUsername() does:
        //   a) Query: SELECT * FROM users WHERE email = ?
        //   b) If not found: throw UsernameNotFoundException
        //   c) If found: return UserDetails with roles/permissions
        return userDetailsService.loadUserByUsername(username);
    }

    /**
     * EXTRACT USERNAME FROM TOKEN (PRIVATE HELPER)
     * ============================================
     * PURPOSE: Parses JWT token and extracts the username/email.
     *
     * PARAMETERS:
     *   @param token - JWT token string
     *
     * RETURNS:
     *   String - Username/email from token's "sub" claim
     *
     * THROWS:
     *   ExpiredJwtException - Token has expired
     *   SignatureException - Token signature is invalid
     *   MalformedJwtException - Token format is wrong
     *
     * THIS IS WHERE TOKEN VALIDATION ACTUALLY HAPPENS!
     * ================================================
     */
    private String extractUsername(String token){

        // STEP 1: Parse and validate the token
        // =====================================
        // Jwts.parserBuilder() creates a JWT parser
        //
        // WHAT HAPPENS DURING PARSING:
        // ----------------------------
        Claims claims = Jwts.parserBuilder()

                // Set the signing key for verification
                // -------------------------------------
                // Same key used to sign must be used to verify
                // This proves the token was created by us
                //
                // If someone tries to modify the token:
                //   - They change payload (e.g., email)
                //   - But they can't recreate signature without secret key
                //   - Signature verification fails here
                //   - SignatureException thrown
                .setSigningKey(getSigningKey())

                // Build the parser
                // ----------------
                .build()

                // Parse and verify the token
                // --------------------------
                // parseClaimsJws(token) does:
                //   1. Splits token into: header, payload, signature
                //   2. Decodes header and payload from Base64
                //   3. Recalculates signature using secret key
                //   4. Compares calculated signature with token's signature
                //   5. If signatures match → token is valid
                //   6. If signatures don't match → SignatureException
                //   7. Checks expiration timestamp
                //   8. If expired → ExpiredJwtException
                //   9. Returns Claims (payload data)
                //
                // VALIDATION TIMELINE:
                // --------------------
                // Token created: 2024-10-29 10:00:00
                // Token expires: 2024-10-30 10:00:00
                //
                // If current time is 2024-10-29 14:00:00:
                //   ✓ Token valid (within 24 hours)
                //
                // If current time is 2024-10-30 12:00:00:
                //   ✗ Token expired (more than 24 hours old)
                //   ✗ ExpiredJwtException thrown
                //   ✗ User must login again to get new token
                .parseClaimsJws(token)

                // Extract the claims (payload)
                // ----------------------------
                // getBody() returns the Claims object
                // Claims contain all the data in the payload:
                //   - sub: username/email
                //   - iat: issued at timestamp
                //   - exp: expiration timestamp
                //   - Any custom claims you added
                .getBody();

        // STEP 2: Extract username from claims
        // =====================================
        // claims.getSubject() gets the "sub" claim
        // This is the username/email we set during token generation
        //
        // Example claims:
        // {
        //   "sub": "user@test.com",     ← This is what we extract
        //   "iat": 1635000000,
        //   "exp": 1635086400
        // }
        return claims.getSubject();
    }

    /**
     * GET SIGNING KEY (PRIVATE HELPER)
     * ================================
     * PURPOSE: Converts the secret string into a cryptographic Key object.
     *
     * RETURNS:
     *   Key - Cryptographic key for signing/verifying tokens
     *
     * WHY WE NEED THIS:
     * -----------------
     * - JWT library requires a Key object, not a plain string
     * - Key object has proper encoding and security properties
     * - Ensures consistent key format for signing and verification
     */
    private Key getSigningKey(){

        // STEP 1: Convert secret string to bytes
        // =======================================
        // secretKey is a String: "mySecretKeyForJwtTokenSigning"
        // getBytes() converts to byte array: [109, 121, 83, 101, ...]
        //
        // WHY BYTES?
        //   - Cryptographic operations work on bytes, not strings
        //   - Removes encoding ambiguity (UTF-8, ASCII, etc.)
        byte[] keyBytes = secretKey.getBytes();

        // STEP 2: Create HMAC-SHA256 key
        // ===============================
        // Keys.hmacShaKeyFor(bytes) creates a Key suitable for HMAC-SHA256
        //
        // WHAT IT DOES:
        //   - Validates key length (must be >= 256 bits for HS256)
        //   - If key too short → WeakKeyException
        //   - Wraps bytes in SecretKeySpec for HMAC algorithms
        //   - Returns Key object ready for signing/verifying
        //
        // KEY LENGTH REQUIREMENTS:
        // ------------------------
        // For HS256 (HMAC-SHA256):
        //   - Minimum: 256 bits = 32 bytes = 32 characters
        //   - Recommended: 512 bits = 64 bytes = 64 characters
        //
        // TOO SHORT:
        //   "secret" → Only 6 bytes → WeakKeyException
        //
        // GOOD LENGTH:
        //   "mySecretKeyForJwtTokenSigningMustBeLongEnough123456" → 52 bytes ✓
        //
        // SECURITY NOTE:
        // --------------
        // The longer the key, the more secure:
        //   - Harder to brute force
        //   - More entropy (randomness)
        //   - Better protection against attacks
        return Keys.hmacShaKeyFor(keyBytes);
    }
}

/**
 * ==========================================
 * COMPLETE JWT AUTHENTICATION FLOW
 * ==========================================
 *
 * SCENARIO 1: USER LOGS IN
 * =========================
 *
 * 1. CLIENT SENDS LOGIN REQUEST:
 *    POST /api/v1/auth
 *    { "email": "user@test.com", "password": "password123" }
 *
 * 2. AuthController.login() CALLS:
 *    UserDetails user = authenticationService.authenticate(email, password);
 *
 * 3. authenticate() METHOD:
 *    a) Creates UsernamePasswordAuthenticationToken
 *    b) authenticationManager.authenticate() verifies credentials
 *       - Queries database for user
 *       - Compares password hash
 *       - Throws exception if invalid
 *    c) Loads full UserDetails from database
 *    d) Returns UserDetails to controller
 *
 * 4. AuthController CALLS:
 *    String token = authenticationService.generateToken(user);
 *
 * 5. generateToken() METHOD:
 *    a) Creates claims (payload data)
 *    b) Sets subject (username), issued at, expiration
 *    c) Signs token with secret key (creates signature)
 *    d) Returns token string: "eyJhbGci..."
 *
 * 6. AuthController RETURNS:
 *    HTTP 200 OK
 *    {
 *      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
 *      "expiresIn": 86400
 *    }
 *
 * 7. CLIENT STORES TOKEN:
 *    localStorage.setItem('token', response.token);
 *
 *
 * SCENARIO 2: USER ACCESSES PROTECTED ENDPOINT
 * =============================================
 *
 * 1. CLIENT SENDS REQUEST WITH TOKEN:
 *    POST /api/v1/posts
 *    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *    { "title": "My Post", "content": "..." }
 *
 * 2. JwtAuthenticationFilter INTERCEPTS:
 *    a) Extracts token from Authorization header
 *    b) Calls: authenticationService.validateToken(token)
 *
 * 3. validateToken() METHOD:
 *    a) extractUsername(token):
 *       - Parses token
 *       - Verifies signature (proves token is authentic)
 *       - Checks expiration (throws exception if expired)
 *       - Extracts username
 *    b) Loads UserDetails from database
 *    c) Returns UserDetails
 *
 * 4. JwtAuthenticationFilter:
 *    a) Creates Authentication object
 *    b) Sets in SecurityContext
 *    c) Allows request to proceed
 *
 * 5. PostController EXECUTES:
 *    a) Can access current user via SecurityContextHolder
 *    b) Creates post
 *    c) Returns response
 *
 * 6. CLIENT RECEIVES:
 *    HTTP 201 Created
 *    { "id": "...", "title": "My Post", ... }
 *
 *
 * SCENARIO 3: TOKEN EXPIRES
 * ==========================
 *
 * 1. CLIENT SENDS REQUEST (25 hours after login):
 *    GET /api/v1/posts
 *    Authorization: Bearer eyJhbGci... (expired token)
 *
 * 2. JwtAuthenticationFilter INTERCEPTS:
 *    a) Extracts token from header
 *    b) Calls: authenticationService.validateToken(token)
 *
 * 3. extractUsername(token):
 *    a) Jwts.parserBuilder().parseClaimsJws(token)
 *    b) Checks expiration timestamp
 *    c) Current time > expiration time
 *    d) Throws ExpiredJwtException
 *
 * 4. EXCEPTION BUBBLES UP:
 *    a) JwtAuthenticationFilter catches it
 *    b) Doesn't set authentication
 *    c) Returns 401 Unauthorized
 *
 * 5. CLIENT RECEIVES:
 *    HTTP 401 Unauthorized
 *    { "status": 401, "message": "Token expired" }
 *
 * 6. CLIENT HANDLES:
 *    - Clears stored token
 *    - Redirects to login page
 *    - User must login again to get fresh token
 *
 *
 * SCENARIO 4: TAMPERED TOKEN (SECURITY ATTACK)
 * =============================================
 *
 * ATTACKER SCENARIO:
 * ------------------
 * Attacker intercepts token and tries to modify it:
 *
 * Original token payload:
 * { "sub": "user@test.com", "exp": 1635086400 }
 *
 * Attacker wants to change to:
 * { "sub": "admin@test.com", "exp": 1735086400 }  ← Changed!
 *
 * 1. ATTACKER MODIFIES TOKEN:
 *    - Decodes payload from Base64
 *    - Changes "user" to "admin"
 *    - Re-encodes payload to Base64
 *    - Creates new token: header.modified_payload.old_signature
 *
 * 2. ATTACKER SENDS REQUEST:
 *    GET /api/v1/admin/users
 *    Authorization: Bearer <tampered_token>
 *
 * 3. JwtAuthenticationFilter INTERCEPTS:
 *    Calls: validateToken(tampered_token)
 *
 * 4. extractUsername(tampered_token):
 *    a) Jwts.parserBuilder().parseClaimsJws()
 *    b) Recalculates signature:
 *       new_signature = HMAC-SHA256(header + modified_payload, secret)
 *    c) Compares: new_signature != old_signature
 *    d) Signatures don't match! 🚨
 *    e) Throws SignatureException
 *
 * 5. ATTACK BLOCKED:
 *    HTTP 401 Unauthorized
 *    { "status": 401, "message": "Invalid token" }
 *
 * WHY IT FAILED:
 * --------------
 * ✓ Attacker doesn't have the secret key
 * ✓ Can't create valid signature for modified payload
 * ✓ Any modification breaks the signature
 * ✓ JWT security works as designed!
 *
 *
 * ==========================================
 * JWT TOKEN ANATOMY (DETAILED BREAKDOWN)
 * ==========================================
 *
 * EXAMPLE TOKEN:
 * --------------
 * eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQHRlc3QuY29tIiwiaWF0IjoxNjM1MDAwMDAwLCJleHAiOjE2MzUwODY0MDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
 *
 * PART 1: HEADER (Red)
 * --------------------
 * eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
 *
 * Decoded (Base64):
 * {
 *   "alg": "HS256",     ← Algorithm: HMAC-SHA256
 *   "typ": "JWT"        ← Type: JSON Web Token
 * }
 *
 * PART 2: PAYLOAD (Purple)
 * -------------------------
 * eyJzdWIiOiJ1c2VyQHRlc3QuY29tIiwiaWF0IjoxNjM1MDAwMDAwLCJleHAiOjE2MzUwODY0MDB9
 *
 * Decoded (Base64):
 * {
 *   "sub": "user@test.com",    ← Subject: who the token is about
 *   "iat": 1635000000,          ← Issued At: Oct 23, 2021 10:00:00 UTC
 *   "exp": 1635086400           ← Expires: Oct 24, 2021 10:00:00 UTC
 * }
 *
 * PART 3: SIGNATURE (Blue)
 * -------------------------
 * SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
 *
 * How it's created:
 * signature = HMAC-SHA256(
 *   base64UrlEncode(header) + "." + base64UrlEncode(payload),
 *   secret_key
 * )
 *
 * This proves:
 * ✓ Token was created by someone with the secret key
 * ✓ Header and payload haven't been modified
 * ✓ Token is trustworthy
 *
 *
 * ==========================================
 * SECURITY BEST PRACTICES
 * ==========================================
 *
 * ✅ CURRENT IMPLEMENTATION DOES:
 * -------------------------------
 * ✓ Uses strong algorithm (HS256)
 * ✓ Sets expiration time (24 hours)
 * ✓ Verifies signature on every request
 * ✓ Checks expiration on every request
 * ✓ Loads fresh user data from database
 * ✓ Separates secret key into config file
 *
 * 🔒 ADDITIONAL RECOMMENDATIONS:
 * ------------------------------
 *
 * 1. SECRET KEY SECURITY:
 *    ❌ Don't hardcode in code
 *    ❌ Don't commit to Git
 *    ✅ Use environment variables
 *    ✅ Use secrets management (AWS Secrets Manager, Vault)
 *    ✅ Rotate regularly (every 3-6 months)
 *    ✅ Use minimum 256 bits (32 characters)
 *
 * 2. TOKEN EXPIRATION:
 *    ✅ Keep short (15 min - 1 hour for sensitive apps)
 *    ✅ Use refresh tokens for longer sessions
 *    ✅ Different expiry for different security levels
 *
 * 3. REFRESH TOKENS:
 *    ✅ Access token: 15 minutes (for API calls)
 *    ✅ Refresh token: 7 days (to get new access token)
 *    ✅ Store refresh tokens in database
 *    ✅ Can revoke refresh tokens
 *
 * 4. TOKEN STORAGE (CLIENT-SIDE):
 *    ✅ Use httpOnly cookies (prevents XSS)
 *    ⚠️ localStorage (vulnerable to XSS, but common)
 *    ❌ sessionStorage (lost on tab close)
 *    ❌ Plain cookies (vulnerable to XSS)
 *
 * 5. ADDITIONAL CLAIMS:
 *    ✅ Add roles/permissions to token
 *    ✅ Add token ID (jti) for revocation
 *    ✅ Add issuer (iss) and audience (aud)
 *    ⚠️ Don't add sensitive data (encrypted if needed)
 *
 * 6. TOKEN REVOCATION:
 *    ✅ Maintain blacklist of revoked tokens
 *    ✅ Store token IDs in Redis with expiration
 *    ✅ Check blacklist before validating
 *    ✅ Allow users to logout (add token to blacklist)
 *
 * 7. RATE LIMITING:
 *    ✅ Limit login attempts (prevent brute force)
 *    ✅ Limit token generation (prevent DOS)
 *    ✅ Track failed validation attempts
 *
 *
 * ==========================================
 * COMMON JWT VULNERABILITIES & FIXES
 * ==========================================
 *
 * VULNERABILITY 1: None Algorithm Attack
 * --------------------------------------
 * Attacker changes algorithm from HS256 to "none":
 * { "alg": "none", "typ": "JWT" }
 *
 * FIX:
 * ✅ Always specify algorithm explicitly (✓ we do: HS256)
 * ✅ Never accept "none" algorithm
 *
 * VULNERABILITY 2: Key Confusion
 * ------------------------------
 * Attacker tricks server to use public key as secret
 *
 * FIX:
 * ✅ Use different algorithms (HS256 vs RS256)
 * ✅ Validate algorithm matches expected
 *
 * VULNERABILITY 3: Weak Secret
 * ---------------------------
 * Short or common secrets can be brute-forced
 *
 * FIX:
 * ✅ Use minimum 256-bit (32 character) secret (✓ enforced by Keys.hmacShaKeyFor)
 * ✅ Use randomly generated secrets
 * ✅ Rotate secrets periodically
 *
 * VULNERABILITY 4: Token Sidejacking
 * ----------------------------------
 * Attacker steals token from network traffic
 *
 * FIX:
 * ✅ Always use HTTPS in production
 * ✅ Set short expiration times
 * ✅ Use refresh tokens
 *
 * VULNERABILITY 5: XSS (Cross-Site Scripting)
 * -------------------------------------------
 * Attacker injects JavaScript to steal tokens from localStorage
 *
 * FIX:
 * ✅ Use httpOnly cookies instead of localStorage
 * ✅ Implement Content Security Policy (CSP)
 * ✅ Sanitize all user input
 *
 *
 * ==========================================
 * IMPLEMENTING REFRESH TOKENS (ADVANCED)
 * ==========================================
 *
 * CONCEPT:
 * --------
 * - Access Token: Short-lived (15 min), used for API calls
 * - Refresh Token: Long-lived (7 days), used to get new access token
 *
 * LOGIN FLOW:
 * -----------
 * 1. User logs in
 * 2. Server generates TWO tokens:
 *    - Access token (expires in 15 min)
 *    - Refresh token (expires in 7 days)
 * 3. Both tokens sent to client
 *
 * API CALL FLOW:
 * --------------
 * 1. Client uses access token for API calls
 * 2. After 15 min, access token expires
 * 3. Client uses refresh token to get new access token
 * 4. Server validates refresh token (check if revoked)
 * 5. Generate new access token
 * 6. Optionally rotate refresh token
 *
 * LOGOUT FLOW:
 * ------------
 * 1. Client sends logout request
 * 2. Server adds refresh token to blacklist
 * 3. Access token still valid until expires (15 min max)
 * 4. After expiry, can't get new token (refresh token blacklisted)
 *
 * EXAMPLE IMPLEMENTATION:
 * -----------------------
 * public String generateRefreshToken(UserDetails userDetails) {
 *     return Jwts.builder()
 *         .setSubject(userDetails.getUsername())
 *         .setIssuedAt(new Date())
 *         .setExpiration(new Date(System.currentTimeMillis() + 604800000L)) // 7 days
 *         .claim("type", "refresh")  // Mark as refresh token
 *         .signWith(getSigningKey(), SignatureAlgorithm.HS256)
 *         .compact();
 * }
 *
 * public boolean isRefreshToken(String token) {
 *     Claims claims = extractAllClaims(token);
 *     return "refresh".equals(claims.get("type"));
 * }
 *
 * public boolean isTokenRevoked(String token) {
 *     String tokenId = extractTokenId(token);
 *     return revokedTokenRepository.existsByTokenId(tokenId);
 * }
 *
 *
 * ==========================================
 * TESTING THIS SERVICE
 * ==========================================
 *
 * UNIT TEST EXAMPLE:
 * ------------------
 * @ExtendWith(MockitoExtension.class)
 * class AuthenticationServiceImplTest {
 *
 *     @Mock
 *     private AuthenticationManager authenticationManager;
 *
 *     @Mock
 *     private UserDetailsService userDetailsService;
 *
 *     @InjectMocks
 *     private AuthenticationServiceImpl authenticationService;
 *
 *     @Test
 *     void shouldAuthenticateValidUser() {
 *         // Given
 *         String email = "user@test.com";
 *         String password = "password";
 *         UserDetails userDetails = mock(UserDetails.class);
 *
 *         when(userDetailsService.loadUserByUsername(email))
 *             .thenReturn(userDetails);
 *
 *         // When
 *         UserDetails result = authenticationService.authenticate(email, password);
 *
 *         // Then
 *         assertNotNull(result);
 *         verify(authenticationManager).authenticate(any());
 *     }
 *
 *     @Test
 *     void shouldGenerateValidToken() {
 *         // Given
 *         UserDetails userDetails = mock(UserDetails.class);
 *         when(userDetails.getUsername()).thenReturn("user@test.com");
 *
 *         // When
 *         String token = authenticationService.generateToken(userDetails);
 *
 *         // Then
 *         assertNotNull(token);
 *         assertTrue(token.split("\\.").length == 3); // header.payload.signature
 *     }
 *
 *     @Test
 *     void shouldValidateCorrectToken() {
 *         // Given
 *         UserDetails userDetails = mock(UserDetails.class);
 *         when(userDetails.getUsername()).thenReturn("user@test.com");
 *         String token = authenticationService.generateToken(userDetails);
 *
 *         when(userDetailsService.loadUserByUsername("user@test.com"))
 *             .thenReturn(userDetails);
 *
 *         // When
 *         UserDetails result = authenticationService.validateToken(token);
 *
 *         // Then
 *         assertNotNull(result);
 *         assertEquals("user@test.com", result.getUsername());
 *     }
 *
 *     @Test
 *     void shouldRejectExpiredToken() {
 *         // Would need to mock time or use a test library
 *         // to create expired tokens for testing
 *     }
 * }
 *
 *
 * ==========================================
 * DEBUGGING TIPS
 * ==========================================
 *
 * PROBLEM: "Token validation fails"
 * ---------------------------------
 * Check:
 * 1. Secret key matches between generation and validation
 * 2. Token hasn't expired (check timestamps)
 * 3. Token format is correct (3 parts separated by dots)
 * 4. No extra spaces in Authorization header
 * 5. "Bearer " prefix is correct (capital B, space after)
 *
 * PROBLEM: "WeakKeyException"
 * ---------------------------
 * Solution:
 * - Secret key must be >= 256 bits (32 characters)
 * - Use longer secret: "mySecretKeyForJwtTokenSigningMustBeLongEnough"
 *
 * PROBLEM: "SignatureException"
 * -----------------------------
 * Causes:
 * - Secret key mismatch
 * - Token was modified
 * - Wrong algorithm used
 *
 * PROBLEM: "ExpiredJwtException"
 * ------------------------------
 * Expected behavior:
 * - Token older than 24 hours
 * - User must login again
 * - Frontend should catch and redirect to login
 *
 * PROBLEM: "User not found after token validation"
 * ------------------------------------------------
 * Causes:
 * - User deleted from database after token issued
 * - Database connection issue
 * - Username extraction from token incorrect
 *
 *
 * ==========================================
 * USEFUL TOOLS FOR JWT DEVELOPMENT
 * ==========================================
 *
 * 1. JWT.IO (https://jwt.io)
 *    - Decode and inspect JWT tokens
 *    - Verify signatures
 *    - Create test tokens
 *
 * 2. Postman
 *    - Test authentication endpoints
 *    - Save tokens in variables
 *    - Automatically add to headers
 *
 * 3. Browser DevTools
 *    - Inspect localStorage/cookies
 *    - View request/response headers
 *    - Network tab to see token in requests
 *
 * 4. Online HMAC-SHA256 Calculator
 *    - Verify signature calculation
 *    - Test with your secret key
 *
 * 5. Base64 Decoder
 *    - Decode header and payload
 *    - Inspect claims
 *
 *
 * ==========================================
 * SUMMARY
 * ==========================================
 *
 * THIS SERVICE IS THE AUTHENTICATION CORE:
 * ----------------------------------------
 *
 * authenticate(email, password):
 *   → Verifies credentials
 *   → Called during LOGIN
 *   → Returns UserDetails if valid
 *   → Throws exception if invalid
 *
 * generateToken(userDetails):
 *   → Creates JWT with user info
 *   → Called after successful login
 *   → Returns signed token string
 *   → Token valid for 24 hours
 *
 * validateToken(token):
 *   → Verifies token signature
 *   → Checks expiration
 *   → Called on EVERY protected request
 *   → Returns UserDetails if valid
 *   → Throws exception if invalid
 *
 * KEY CONCEPTS:
 * -------------
 * ✓ JWT = Self-contained authentication token
 * ✓ Signature = Proves authenticity and integrity
 * ✓ Expiration = Limits token lifetime
 * ✓ Stateless = Server doesn't store sessions
 * ✓ Secret Key = Critical for security
 *
 * YOU NOW UNDERSTAND:
 * -------------------
 * ✓ How login authentication works
 * ✓ How JWT tokens are created
 * ✓ How tokens are validated
 * ✓ Why signature
 **/