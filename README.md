# GoAuth HTTP

HTTP REST API version of GoAuth - Authentication service with MongoDB Atlas and Google OAuth support.

## Endpoints

### POST /api/auth/register
Register a new user
```json
{
  "username": "testuser",
  "password": "testpass",
  "email": "test@example.com"
}
```
Response:
```json
{
  "status": true,
  "token": "jwt_token"
}
```

### POST /api/auth/login
Login with username and password
```json
{
  "username": "testuser",
  "password": "testpass"
}
```
Response:
```json
{
  "status": true,
  "token": "jwt_token"
}
```

### POST /api/auth/google
Google OAuth login
```json
{
  "id_token": "google_id_token_here"
}
```
Response:
```json
{
  "access_token": "jwt_token",
  "refresh_token": "jwt_token",
  "user": {
    "id": "...",
    "username": "...",
    "email": "...",
    "role": "...",
    "google_id": "...",
    "picture": "..."
  }
}
```

### POST /api/auth/logout
Logout (requires Bearer token)
```json
{}
```
Response:
```json
{
  "status": true
}
```

### POST /api/auth/change-role
Change user role (requires admin Bearer token)
```json
{
  "id": "user_id",
  "role": "admin"
}
```
Response:
```json
{
  "status": true
}
```

### POST /api/auth/verify
Verify a JWT token and get user details. Returns user info if valid, 401 if invalid or expired.
```json
{
  "token": "jwt_token_here"
}
```
Response:
```json
{
  "status": true,
  "id": "...",
  "username": "...",
  "role": "..."
}
```

## Running Locally

```bash
go run cmd/api/main.go
```

## Running with Docker

```bash
docker-compose up
```
