# SecureBlog

[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.java.net/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Spring Security](https://img.shields.io/badge/Spring%20Security-6.x-green.svg)](https://spring.io/projects/spring-security)
[![JWT](https://img.shields.io/badge/JWT-Stateless-blue.svg)](https://jwt.io/)

A RESTful blog API built to explore JWT-based stateless authentication and clean layered architecture in Spring Boot. The project covers the full security lifecycle — credential validation, token issuance, per-request filter-chain verification — alongside role-based access control and a post management domain with draft/published workflow.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Java 21 |
| Framework | Spring Boot 3.x |
| Security | Spring Security 6.x, JJWT |
| Persistence | Spring Data JPA, Hibernate |
| Database | PostgreSQL (Docker) |
| Mapping | MapStruct |
| Build | Maven |
| Utilities | Lombok, Thymeleaf |

---

## Architecture

```
Client
  └── HTTP + Bearer Token
        └── JwtAuthenticationFilter          ← validates token, populates SecurityContext
              └── Controllers
                    └── Services
                          └── Repositories
                                └── PostgreSQL
```

Request flow: every non-public request passes through `JwtAuthenticationFilter` before reaching the controller. The filter extracts the token, delegates validation to `JwtUtil`, and sets the `UsernamePasswordAuthenticationToken` in the security context. Spring Security's method-level annotations then enforce role checks.

---

## Authentication Flow

1. `POST /api/v1/auth/login` with credentials
2. `AuthServiceImpl` validates via `BlogUserDetailsService` + BCrypt comparison
3. On success, `JwtUtil` signs a token with the user's roles as claims
4. Client attaches `Authorization: Bearer <token>` on subsequent requests
5. `JwtAuthenticationFilter` validates signature and expiry per request — no session stored server-side

---

## API Endpoints

### Auth
| Method | Endpoint | Access | Description |
|--------|----------|--------|-------------|
| POST | `/api/v1/auth/login` | Public | Issue JWT |

### Posts
| Method | Endpoint | Access | Description |
|--------|----------|--------|-------------|
| GET | `/api/v1/posts` | Public | All published posts |
| GET | `/api/v1/posts/{id}` | Public | Single post |
| GET | `/api/v1/posts/drafts` | User | Caller's drafts |
| POST | `/api/v1/posts` | User | Create post |
| PUT | `/api/v1/posts/{id}` | User/Admin | Update post |
| DELETE | `/api/v1/posts/{id}` | User/Admin | Delete post |

### Categories & Tags
| Method | Endpoint | Access | Description |
|--------|----------|--------|-------------|
| GET | `/api/v1/categories` | Public | All categories |
| POST | `/api/v1/categories` | Admin | Create category |
| PUT | `/api/v1/categories/{id}` | Admin | Update category |
| DELETE | `/api/v1/categories/{id}` | Admin | Delete category |
| GET | `/api/v1/tags` | Public | All tags |
| POST | `/api/v1/tags` | Admin | Create tag |
| DELETE | `/api/v1/tags/{id}` | Admin | Delete tag |

---

## Sample Requests

**Login**
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "secret"}'
```
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "email": "user@example.com",
  "role": "USER"
}
```

**Create Post (authenticated)**
```bash
curl -X POST http://localhost:8080/api/v1/posts \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Getting started with JWT",
    "content": "...",
    "categoryId": 1,
    "tagIds": [2, 5],
    "status": "DRAFT"
  }'
```
```json
{
  "id": 12,
  "title": "Getting started with JWT",
  "status": "DRAFT",
  "author": "user@example.com",
  "createdAt": "2025-04-05T10:30:00Z"
}
```

**Error Response (standardized)**
```json
{
  "status": 403,
  "error": "Forbidden",
  "message": "Access denied — ADMIN role required",
  "timestamp": "2025-04-05T10:31:00Z"
}
```

---

## Running Locally

**Prerequisites:** Java 21, Maven 3.9+, Docker Desktop

```bash
# Start PostgreSQL
docker compose up -d postgres

# Run the API
mvn spring-boot:run

# Stop
docker compose down
```

Default DB config (see `docker-compose.yml`): database `blogdb`, user `bloguser`, password `blogpass`, port `5432`.

---

## Project Structure

```
src/main/java/com/secureblog/
├── controllers/        # AuthController, PostController, CategoryController, TagController
├── services/           # Interfaces + impl/ with business logic
├── repositories/       # Spring Data JPA interfaces
├── entities/           # User, Post, Category, Tag, Role (enum), PostStatus (enum)
├── security/           # JwtAuthenticationFilter, JwtUtil, BlogUserDetailsService
├── config/             # SecurityConfig — filter chain, public route matchers
├── mappers/            # MapStruct mappers (compile-time, no reflection overhead)
└── dtos/
    ├── request/        # LoginRequest, CreatePostRequest, UpdatePostRequest
    └── response/       # AuthResponse, PostDto, ApiErrorResponse
```

---

## Design Decisions

**MapStruct over ModelMapper** — compile-time generation avoids runtime reflection. Mapping errors surface at build time, not in production.

**Stateless JWT over sessions** — simpler horizontal scaling; no session store needed. Tradeoff: token revocation requires short expiry + refresh token infrastructure (not yet implemented).

**Draft/Published enum on Post** — makes status transitions explicit and queryable. Avoids boolean flags that accumulate over time.

---

## What's Missing / Next Steps

- Refresh token endpoint and token revocation strategy
- Pagination on `GET /posts` (currently unbounded)
- Search by tag/category with `Specification` API
- Rate limiting on auth endpoint
- Integration tests with `@SpringBootTest` + Testcontainers

---

## Author

**Abbas Zaidi** — [GitHub](https://github.com/AbbasZaidi11) · [LinkedIn](https://www.linkedin.com/in/abbaszaidi11)