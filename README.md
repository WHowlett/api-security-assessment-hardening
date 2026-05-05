# API Security Assessment & Hardening

## Overview
This project demonstrates the design, exploitation, and hardening of a REST API built with Node.js and Express. It focuses on identifying common API security weaknesses and implementing layered security controls to mitigate them.

## Objectives
- Simulate insecure API behavior
- Identify and demonstrate vulnerabilities
- Implement security controls
- Validate protections with testing
- Document findings and improvements

## Technologies Used
- Node.js / Express
- JSON Web Tokens (JWT)
- Zod (input validation)
- Express Rate Limit
- dotenv
- Thunder Client (testing)

## Key Security Controls Implemented
- JWT-based Authentication
- Role-Based Access Control (RBAC)
- Rate Limiting (Brute Force Protection)
- Input Validation (Zod)
- Security Event Logging

## Vulnerabilities Identified
- Missing Authentication (initial /profile exposure)
- Weak Authorization Controls
- No Rate Limiting
- Lack of Input Validation

## Security Improvements
| Control | Description |
|--------|------------|
| Authentication | Implemented JWT tokens |
| Authorization | Restricted admin-only endpoints |
| Rate Limiting | Limited login attempts |
| Input Validation | Enforced schema validation |
| Logging | Added security event logs |

## Example Security Events Logged
- Failed login attempts
- Invalid input submissions
- Missing token access attempts
- Unauthorized admin access

## Testing
Tested using Thunder Client:
- Login success/failure
- Token validation
- Role-based access enforcement
- Rate limit triggering
- Input validation errors

## Screenshots
See `/screenshots` folder for:
- API running
- Login success
- Broken access (before fix)
- Authorized access
- Admin denial
- Rate limiting
- Security logging

## Lessons Learned
This project highlights the importance of layered security in API design. Authentication alone is not sufficient — proper validation, authorization, rate limiting, and logging are critical for protecting modern applications.

## Author
Wayne Howlett  
API & Cloud Security Engineer