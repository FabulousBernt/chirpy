# Chirpy API

A REST API for a Twitter-like social media platform. Users can create accounts, post "chirps" (short messages), and authenticate using JWT tokens.

## Features

- **User Authentication** - Registration, login with secure password hashing (Argon2)
- **JWT Tokens** - Access tokens with refresh token support
- **Chirps** - Create, read, delete chirps with filtering and sorting
- **Chirpy Red Membership** - Webhook integration with Polka for premium subscriptions

## Tech Stack

- **Language**: Go
- **Database**: PostgreSQL
- **Authentication**: JWT (golang-jwt), Argon2 password hashing
- **Database Migrations**: Goose
- **Code Generation**: SQLC

## Prerequisites

- Go 1.25+
- PostgreSQL

## Setup

1. **Clone and install dependencies**:
   ```bash
   go mod download
   ```

2. **Configure environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your values
   ```

3. **Generate a JWT secret**:
   ```bash
   openssl rand -base64 64
   # Copy the output and set it as JWT_SECRET in .env
   ```

4. **Create database and run migrations**:
   ```bash
   createdb chirpy
   cd sql
   goose postgres "postgres://user:pass@localhost:5432/chirpy?sslmode=disable" up
   ```

5. **Run the server**:
   ```bash
   go build && ./chirpy
   ```

The API runs on `http://localhost:8080`.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `DB_URL` | PostgreSQL connection string |
| `PLATFORM` | Set to `dev` to enable admin endpoints |
| `JWT_SECRET` | Secret key for signing JWTs (generate with `openssl rand -base64 64`) |
| `POLKA_KEY` | API key for validating Polka webhooks |

## API Endpoints

### Users

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/users` | No | Create new user |
| PUT | `/api/users` | JWT | Update user email/password |
| POST | `/api/login` | No | Login and get tokens |

### Chirps

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/chirps` | No | List chirps |
| GET | `/api/chirps/{id}` | No | Get single chirp |
| POST | `/api/chirps` | JWT | Create chirp |
| DELETE | `/api/chirps/{id}` | JWT | Delete chirp |

### Tokens

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/refresh` | Refresh Token | Get new access token |
| POST | `/api/revoke` | Refresh Token | Revoke refresh token |

### Admin

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/admin/metrics` | No | Server metrics |
| POST | `/admin/reset` | No (dev only) | Reset database |
| POST | `/api/polka/webhooks` | API Key | Handle Polka webhooks |

## Query Parameters

**GET /api/chirps**:
- `author_id` - Filter chirps by user ID
- `sort` - Sort order: `asc` (default) or `desc`
