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

### POST /api/auth/login
Login with username and password
```json
{
  "username": "testuser",
  "password": "testpass"
}
```

### POST /api/auth/google
Google OAuth login
```json
{
  "id_token": "google_id_token_here"
}
```

### POST /api/auth/logout
Logout (requires Bearer token)
```json
{}
```

### POST /api/auth/change-role
Change user role (requires admin Bearer token)
```json
{
  "id": "user_id",
  "role": "admin"
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
