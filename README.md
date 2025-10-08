Java Code Host
Production-ready Spring Boot application for hosting and sharing Java programs, with features for uploading and downloading programs, ZIP files, .java files, and full repositories similar to GitHub. The website features a dark-colored theme.
Overview
This application is a secure, self-hosted platform for managing Java code repositories. It supports:

Admin authentication for uploads.
Public viewing and downloading of repositories and files.
Automatic extraction of ZIP uploads to create repository structures.
Dark-themed frontend for better user experience.

Assumptions:

Single admin user for simplicity (extend to multi-user in production).
Filesystem-based storage (migrate to cloud storage like S3 for scalability).
No code execution on server (view-only).

Requirements

Java 17+
Gradle (for building)
Optional: Docker for deployment

Build and Run

Generate Gradle Wrapper (if not present):
textgradle wrapper

Build the Project:
text./gradlew build

Run the Application:
textjava -jar build/libs/codehost-0.0.1-SNAPSHOT.jar

Access the Website:

Open http://localhost:8080/ in your browser.
Default admin credentials: username admin, password password (change in production).



Usage
Admin Features

Login: Use /api/auth/login endpoint or the frontend form to obtain a JWT token.
Upload: Select a file (ZIP or individual) and repository name. ZIP files are extracted automatically.

Public Features

List Files: /api/repos/public/list/{repoName} to list files in a repository.
Download: /api/repos/public/download/{repoName}/{fileName} to download a file.

Frontend includes sections for login, upload, and repository listing.
Security Notes

Authentication: JWT-based with 24-hour expiration. Change secret key in JwtUtil.
Password: Admin password hashed with BCrypt. Update hash in AuthService for production.
File Handling: Path normalization and checks prevent traversal attacks. Validate inputs to avoid injection.
HTTPS: Enable in production via application.properties (server.ssl.* properties).
Rate Limiting: Add via Spring Boot filters if needed (stubbed in config).
Storage: Files stored in ./storage/ – secure directory permissions.
Best Practices: No execution of uploaded code. Use secure defaults for cryptography (HS256 for JWT).

Deployment Tips

Docker: Create a Dockerfile:
textFROM openjdk:17-jdk-slim
COPY build/libs/codehost-0.0.1-SNAPSHOT.jar app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
Build and run:
textdocker build -t codehost .
docker run -p 8080:8080 codehost

Cloud: Deploy to Heroku/AWS/EC2. Integrate with S3 for storage (update FileStorageService).
CI/CD: Use GitHub Actions or Jenkins with Gradle build steps.
Monitoring: Add Spring Boot Actuator for health checks.

Features

Repository Management: Create repos via uploads; support nested structures from ZIP.
File Types: .java, ZIP, and others.
Frontend: Static HTML/JS/CSS with dark theme (black/gray palette).
API Endpoints: RESTful for auth, upload, list, download.
Error Handling: Custom exceptions (IOException, SecurityException) mapped to HTTP statuses; logging via SLF4J.

Error Handling Strategies

Input Validation: Check for invalid names/paths; throw SecurityException on violations.
IO Errors: Catch and return 500 with message; log details.
Auth Failures: 401 on invalid credentials/token.
Not Found: 404 for missing repos/files.
Defensive Checks: Normalize paths; ensure targets within repo dir.

Technical Explanation
The application uses Spring Boot for the backend, with embedded Tomcat. Layers:

Controllers: Handle API requests (AuthController, RepoController).
Services: Business logic (AuthService for login, FileStorageService for storage/extraction).
Util: JWT handling with filters for authentication.
Config: Security (stateless, JWT filter) and CORS.

Frontend is static, served from resources/static, with JS for API interactions. Storage is filesystem-based in ./storage/{repoName}. ZIP extraction uses Apache Commons Compress.
Design Choices:

Security: JWT over sessions for statelessness; BCrypt for hashing.
Concurrency: Services are thread-safe; no shared mutable state.
Error Handling: Centralized via exceptions and HTTP responses.
Scalability: Hooks for DB/S3; current impl suitable for small-scale.
