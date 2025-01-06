# Auth Microservice API

An **open-source authentication and authorization microservice API** built with **NestJS** and **PassportJS**. This API provides robust user authentication, role-based access control (RBAC), and supports multiple authentication strategies.

---

## **Table of Contents**

1. [Features](#features)
2. [Technologies](#technologies)
3. [Getting Started](#getting-started)
4. [Environment Variables](#environment-variables)
5. [Endpoints Overview](#endpoints-overview)
6. [Usage Examples](#usage-examples)
7. [Swagger Documentation](#swagger-documentation)
8. [RBAC (Role-Based Access Control)](#rbac-role-based-access-control)
9. [Contributing](#contributing)
10. [License](#license)

---

## **Features**

- **Local authentication** with email and password.
- **JWT-based access and refresh tokens** for session management.
- **Token blacklisting** for invalidating compromised tokens.
- **Role-Based Access Control (RBAC)** for managing user permissions.
- **Integration-ready** for social logins like Google, Facebook, GitHub (extensible).
- **MongoDB** for data storage.
- **Redis** for caching and token invalidation.
- Comprehensive **Swagger API documentation**.

---

## **Technologies**

- **NestJS**: Backend framework.
- **PassportJS**: Authentication middleware.
- **JWT (JSON Web Tokens)**: Secure access and refresh tokens.
- **MongoDB**: Database.
- **Redis**: Cache storage for token management.
- **Swagger**: API documentation.

---

## **Getting Started**

### **1. Prerequisites**

- [Node.js](https://nodejs.org/) v18+
- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)

### **2. Clone the Repository**

```bash
$ git clone https://github.com/your-repository/auth-microservice.git
$ cd auth-microservice
```

### **3. Install Dependencies**

```bash
$ npm install
```

### **4. Run the Application (Development Mode)**

```bash
$ docker compose up -d --build
```

This will build and start the App, MongoDB, and Redis.

---

## **Environment Variables**

Create a `.env` file in the project root and configure the following variables:

```env
#Database URI
MONGO_URI="mongodb://root:password@localhost:27017/nestdb?authSource=admin"

#Redis Configuration
REDIS_HOST="localhost"
REDIS_PORT="6379"
REDIS_TTL="900_000" # 15 minutes

#JWT Configuration
JWT_SECRET="ZgcI4otHHeQAC1Pf4Ijsb/hcluGoCe13WcK8LHiBFCUkpyekQYQFijKVgbvJud7LvZFPw4Be3X/TSTjjPaNiUObCC0hWGgke"
REFRESH_TOKEN_SECRET="XcziglfyenMyDS66VTb3qXzH2YSpsC/x7YABh4UVYeyrGpvJlwf3mERCEw2N5DM+5WvFoLMEiHkRNCcD5lNJpRdChTBENWkz"
```

## **Usage Examples**

### **Login**

**Request:**

```http
POST /auth/login
Content-Type: application/json

{
  "email": "john.doe@example.com",
  "password": "StrongPassword123!"
}
```

**Response:**

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### **Refresh Token**

**Request:**

```http
POST /auth/refresh
Authorization: Bearer: refreshToken
```

**Response:**

```json
{
  "accessToken": "newAccessTokenString..."
}
```

### **Logout**

**Request:**

```http
POST /auth/logout
Authorization: Bearer accessToken
```

**Response:**

```json
{
  "message": "Logged out successfully"
}
```

---

## **Swagger Documentation**

- Swagger UI is available at `http://localhost:3000/api`.
- Endpoints include detailed request and response schemas.

To view or test endpoints.

---

## **RBAC (Role-Based Access Control)**

- Roles available: `ADMIN`, `MODERATOR`, `USER`.
- Use the `@Roles()` decorator in your controller to restrict routes:

**Example:**

```typescript
@Patch(':id')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.ADMIN)
async updateUser(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
  return this.usersService.updateUser(id, updateUserDto);
}
```

---

## **Contributing**

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'Add feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

---

## **License**

This project is licensed under the MIT License. See `LICENSE` for more details.

---

Feel free to open issues or contribute by submitting pull requests!
