🔐 UserServiceJWT: Advanced Identity & Access Management (IAM)
A high-performance, stateless authentication and authorization engine built with Spring Boot 3.2.4 and Spring Security 6. This service is designed to function as an Identity Provider (IdP) within a Microservices architecture.

🛠 Technical Core Stack
 - Backend: Java 17 (LTS)

 - Framework: Spring Boot 3.2.4

 - Security: Spring Security 6.x (Method-level & Filter-based)

 - Token Management: Auth0 Java-JWT (HS256 HMAC)

 - Persistence: Spring Data JPA + Hibernate 6

 - Database: MySQL 8.x

 - Boilerplate: Project Lombok

🚀 Key Architectural Features

1. Stateless Security Filter Chain
   
Unlike traditional session-based security, this implementation is entirely Stateless. Every request is validated through a custom AuthorizationFilter that intercepts the Bearer token, decodes the claims, and reconstructs the SecurityContext on the fly.

3. Dual-Token Strategy (Access & Refresh)
   
#### To balance security and user experience, the system implements a dual-token flow:

 - Access Token: Short-lived (10 mins) containing user roles/authorities.

 - Refresh Token: Long-lived (7 days) used to rotate access tokens without re-authentication.

3. Role-Based Access Control (RBAC)
The service enforces strict separation of concerns through granular authority mapping:

ROLE_USER: Standard access to personal profile data.

ROLE_ADMIN: Permission to execute POST operations and user management.

ROLE_SUPER_ADMIN: Full system override capabilities.

4. Cryptographic Integrity
Password Hashing: Implements BCryptPasswordEncoder with a strength factor of 10, preventing rainbow table attacks.

Signature Verification: All tokens are signed using HMAC256 with a server-side secret key to prevent payload tampering.

