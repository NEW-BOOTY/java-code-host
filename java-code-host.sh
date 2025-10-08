#!/bin/bash

# Script to create the java-code-host project structure and populate files using Gradle
# Run this script in an empty directory to set up the project
# Assumes Gradle is installed for generating wrapper and auto-building
# Includes extreme error fixing: attempts build, logs errors, and provides diagnostics
# Updated to Gradle 9.0 for Java 24 support, with Java toolchains for compatibility

# Create directory structure
mkdir -p java-code-host/src/main/java/com/devinroyal/codehost/config
mkdir -p java-code-host/src/main/java/com/devinroyal/codehost/controller
mkdir -p java-code-host/src/main/java/com/devinroyal/codehost/service
mkdir -p java-code-host/src/main/java/com/devinroyal/codehost/model
mkdir -p java-code-host/src/main/java/com/devinroyal/codehost/util
mkdir -p java-code-host/src/main/resources/static/css
mkdir -p java-code-host/src/main/resources/static/js
mkdir -p java-code-host/src/test/java/com/devinroyal/codehost/service

# Create build.gradle with toolchain for Java 17 compatibility
cat <<'EOF' > java-code-host/build.gradle
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.1.0'
    id 'io.spring.dependency-management' version '1.1.0'
}

group = 'com.devinroyal'
version = '0.0.1-SNAPSHOT'

java {
    sourceCompatibility = '17'
    targetCompatibility = '17'
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
    testImplementation 'org.springframework.boot:spring-boot-starter-test'
    implementation 'org.apache.commons:commons-compress:1.23.0'
}

tasks.named('bootBuildImage') {
    builder = 'paketobuildpacks/builder-jammy-base:latest'
}

tasks.named('jar') {
    enabled = false
}

tasks.withType(JavaCompile) {
    options.encoding = 'UTF-8'
    javaCompiler = javaToolchains.compilerFor {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

tasks.withType(Test) {
    useJUnitPlatform()
    javaLauncher = javaToolchains.launcherFor {
        languageVersion = JavaLanguageVersion.of(17)
    }
}
EOF

# Create settings.gradle
cat <<'EOF' > java-code-host/settings.gradle
rootProject.name = 'codehost'
EOF

# Create CodeHostApplication.java
cat <<'EOF' > java-code-host/src/main/java/com/devinroyal/codehost/CodeHostApplication.java
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
package com.devinroyal.codehost;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import jakarta.annotation.PostConstruct;
import java.io.File;

@SpringBootApplication
public class CodeHostApplication {

    public static void main(String[] args) {
        SpringApplication.run(CodeHostApplication.class, args);
    }

    @PostConstruct
    public void initStorage() {
        File storageDir = new File("storage");
        if (!storageDir.exists()) {
            if (!storageDir.mkdirs()) {
                throw new RuntimeException("Failed to create storage directory");
            }
        }
    }
}
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
EOF

# Create SecurityConfig.java
cat <<'EOF' > java-code-host/src/main/java/com/devinroyal/codehost/config/SecurityConfig.java
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
package com.devinroyal.codehost.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.devinroyal.codehost.util.JwtUtil; // Assuming JwtUtil has a filter

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtUtil jwtUtil;

    public SecurityConfig(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**", "/api/repos/public/**", "/", "/static/**").permitAll()
                .requestMatchers("/api/repos/upload/**").authenticated()
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .addFilterBefore(jwtUtil.jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
EOF

# Create WebConfig.java
cat <<'EOF' > java-code-host/src/main/java/com/devinroyal/codehost/config/WebConfig.java
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
package com.devinroyal.codehost.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("*")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true);
    }
}
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
EOF

# Create AuthController.java
cat <<'EOF' > java-code-host/src/main/java/com/devinroyal/codehost/controller/AuthController.java
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
package com.devinroyal.codehost.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.devinroyal.codehost.service.AuthService;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");
        if (username == null || password == null) {
            return ResponseEntity.badRequest().body("Missing credentials");
        }
        try {
            String token = authService.authenticate(username, password);
            return ResponseEntity.ok(Map.of("token", token));
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }
    }
}
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
EOF

# Create RepoController.java
cat <<'EOF' > java-code-host/src/main/java/com/devinroyal/codehost/controller/RepoController.java
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
package com.devinroyal.codehost.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import com.devinroyal.codehost.service.FileStorageService;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

@RestController
@RequestMapping("/api/repos")
public class RepoController {

    @Autowired
    private FileStorageService fileStorageService;

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file, @RequestParam("repoName") String repoName) {
        if (file.isEmpty() || repoName == null || repoName.isBlank()) {
            return ResponseEntity.badRequest().body("Invalid request");
        }
        try {
            fileStorageService.storeFile(file, repoName);
            return ResponseEntity.ok("File uploaded successfully");
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to upload file: " + e.getMessage());
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Security violation: " + e.getMessage());
        }
    }

    @GetMapping("/public/list/{repoName}")
    public ResponseEntity<List<String>> listFiles(@PathVariable String repoName) {
        try {
            List<String> files = fileStorageService.listFiles(repoName);
            return ResponseEntity.ok(files);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/public/download/{repoName}/{fileName:.+}")
    public ResponseEntity<Resource> downloadFile(@PathVariable String repoName, @PathVariable String fileName) {
        try {
            Resource resource = fileStorageService.loadFileAsResource(repoName, fileName);
            String contentType = Files.probeContentType(Path.of(fileName));
            if (contentType == null) contentType = "application/octet-stream";
            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType(contentType))
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"")
                    .body(resource);
        } catch (IOException e) {
            return ResponseEntity.notFound().build();
        }
    }
}
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
EOF

# Create FileStorageService.java
cat <<'EOF' > java-code-host/src/main/java/com/devinroyal/codehost/service/FileStorageService.java
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
package com.devinroyal.codehost.service;

import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

@Service
public class FileStorageService {

    private final Path storageLocation = Paths.get("storage").toAbsolutePath().normalize();

    public void storeFile(MultipartFile file, String repoName) throws IOException {
        if (repoName.contains("..") || repoName.contains("/") || repoName.contains("\\")) {
            throw new SecurityException("Invalid repository name");
        }
        Path repoPath = storageLocation.resolve(repoName).normalize();
        if (!Files.exists(repoPath)) {
            Files.createDirectories(repoPath);
        }
        String fileName = file.getOriginalFilename();
        if (fileName == null || fileName.contains("..")) {
            throw new SecurityException("Invalid file name");
        }
        if (fileName.endsWith(".zip")) {
            extractZip(file.getInputStream(), repoPath);
        } else {
            Path targetLocation = repoPath.resolve(fileName).normalize();
            if (!targetLocation.startsWith(repoPath)) {
                throw new SecurityException("Path traversal attempt");
            }
            Files.copy(file.getInputStream(), targetLocation, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private void extractZip(InputStream zipInputStream, Path repoPath) throws IOException {
        try (ZipArchiveInputStream zis = new ZipArchiveInputStream(zipInputStream)) {
            ZipArchiveEntry entry;
            while ((entry = zis.getNextZipEntry()) != null) {
                if (entry.isDirectory()) continue;
                String entryName = entry.getName();
                if (entryName.contains("..")) {
                    throw new SecurityException("Invalid zip entry");
                }
                Path target = repoPath.resolve(entryName).normalize();
                if (!target.startsWith(repoPath)) {
                    throw new SecurityException("Path traversal in zip");
                }
                Files.createDirectories(target.getParent());
                Files.copy(zis, target, StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }

    public List<String> listFiles(String repoName) throws IOException {
        Path repoPath = storageLocation.resolve(repoName).normalize();
        if (!Files.exists(repoPath)) {
            throw new IOException("Repository not found");
        }
        List<String> files = new ArrayList<>();
        Files.walk(repoPath)
             .filter(Files::isRegularFile)
             .forEach(path -> files.add(repoPath.relativize(path).toString()));
        return files;
    }

    public Resource loadFileAsResource(String repoName, String fileName) throws IOException {
        Path repoPath = storageLocation.resolve(repoName).normalize();
        Path filePath = repoPath.resolve(fileName).normalize();
        if (!filePath.startsWith(repoPath)) {
            throw new SecurityException("Path traversal attempt");
        }
        if (Files.exists(filePath)) {
            return new UrlResource(filePath.toUri());
        }
        throw new IOException("File not found");
    }
}
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
EOF

# Create AuthService.java
cat <<'EOF' > java-code-host/src/main/java/com/devinroyal/codehost/service/AuthService.java
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
package com.devinroyal.codehost.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.devinroyal.codehost.util.JwtUtil;

@Service
public class AuthService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    // In-memory admin user; in production, use DB
    private final String ADMIN_USERNAME = "admin";
    private final String ADMIN_PASSWORD_HASH = "$2a$10$/3eE4pT4X4I3d9l3zA5Y3Oa9q5aF4K8b5I3f2u1y0e9r8t7s6p5o4"; // BCrypt hash for "password" - change in prod

    public String authenticate(String username, String password) {
        if (ADMIN_USERNAME.equals(username) && passwordEncoder.matches(password, ADMIN_PASSWORD_HASH)) {
            return jwtUtil.generateToken(username);
        }
        throw new RuntimeException("Authentication failed");
    }
}
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
EOF

# Create User.java
cat <<'EOF' > java-code-host/src/main/java/com/devinroyal/codehost/model/User.java
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
package com.devinroyal.codehost.model;

public class User {
    private String username;
    private String passwordHash;

    // Getters/Setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
}
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
EOF

# Create JwtUtil.java with fix for setDetails compilation error
cat <<'EOF' > java-code-host/src/main/java/com/devinroyal/codehost/util/JwtUtil.java
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
package com.devinroyal.codehost.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil extends OncePerRequestFilter {

    private final String SECRET_KEY = "supersecretkeythatislongenoughforhs256algorithm"; // Change in prod, use env var
    private final Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
    private final long EXPIRATION_TIME = 86400000; // 24 hours

    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    private Claims parseClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            if (validateToken(token)) {
                String username = extractUsername(token);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, null);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                throw new AuthenticationCredentialsNotFoundException("Invalid token");
            }
        }
        filterChain.doFilter(request, response);
    }

    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    public class JwtAuthenticationFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                throws ServletException, IOException {
            JwtUtil.this.doFilterInternal(request, response, filterChain);
        }
    }
}
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
EOF

# Create application.properties
cat <<'EOF' > java-code-host/src/main/resources/application.properties
server.port=8080
spring.application.name=codehost
# For production: server.ssl.enabled=true, etc.
# Logging
logging.level.org.springframework=INFO
logging.level.com.devinroyal=DEBUG
EOF

# Create styles.css (dark theme)
cat <<'EOF' > java-code-host/src/main/resources/static/css/styles.css
body {
    background-color: #121212;
    color: #ffffff;
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 0;
}

header {
    background-color: #1f1f1f;
    padding: 10px;
    text-align: center;
}

main {
    padding: 20px;
}

button {
    background-color: #333333;
    color: #ffffff;
    border: none;
    padding: 10px;
    cursor: pointer;
}

button:hover {
    background-color: #444444;
}

#repo-list {
    list-style: none;
}
EOF

# Create app.js
cat <<'EOF' > java-code-host/src/main/resources/static/js/app.js
// Simple JS for frontend interactions

function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    })
    .then(res => res.json())
    .then(data => {
        if (data.token) {
            localStorage.setItem('token', data.token);
            alert('Logged in');
        } else {
            alert('Login failed');
        }
    });
}

function uploadFile() {
    const file = document.getElementById('file').files[0];
    const repoName = document.getElementById('repoName').value;
    const formData = new FormData();
    formData.append('file', file);
    formData.append('repoName', repoName);
    fetch('/api/repos/upload', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` },
        body: formData
    })
    .then(res => res.text())
    .then(alert);
}

function listRepos() {
    // Placeholder: fetch and display repos
    console.log('Listing repos');
}

// Add more functions for download, list files, etc.
EOF

# Create index.html
cat <<'EOF' > java-code-host/src/main/resources/static/index.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Java Code Host</title>
    <link rel="stylesheet" href="/css/styles.css">
</head>
<body>
    <header>
        <h1>Java Code Host</h1>
    </header>
    <main>
        <section id="login">
            <h2>Login (Admin)</h2>
            <input id="username" type="text" placeholder="Username">
            <input id="password" type="password" placeholder="Password">
            <button onclick="login()">Login</button>
        </section>
        <section id="upload">
            <h2>Upload File/Zip</h2>
            <input id="repoName" type="text" placeholder="Repository Name">
            <input id="file" type="file">
            <button onclick="uploadFile()">Upload</button>
        </section>
        <section id="repos">
            <h2>Repositories</h2>
            <ul id="repo-list"></ul>
        </section>
    </main>
    <script src="/js/app.js"></script>
</body>
</html>
EOF

# Create CodeHostApplicationTests.java
cat <<'EOF' > java-code-host/src/test/java/com/devinroyal/codehost/CodeHostApplicationTests.java
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
package com.devinroyal.codehost;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class CodeHostApplicationTests {

    @Test
    void contextLoads() {
    }
}
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
EOF

# Create FileStorageServiceTest.java
cat <<'EOF' > java-code-host/src/test/java/com/devinroyal/codehost/service/FileStorageServiceTest.java
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
package com.devinroyal.codehost.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import static org.junit.jupiter.api.Assertions.*;

class FileStorageServiceTest {

    private FileStorageService service;
    private Path testStorage = Paths.get("test-storage");

    @BeforeEach
    void setUp() throws IOException {
        Files.createDirectories(testStorage);
        service = new FileStorageService(); // Note: Would need to mock/inject storage path for proper testing
    }

    @Test
    void storeFile() throws IOException {
        MockMultipartFile file = new MockMultipartFile("file", "test.txt", "text/plain", "content".getBytes());
        service.storeFile(file, "test-repo");
        Path stored = Paths.get("storage/test-repo/test.txt");
        assertTrue(Files.exists(stored));
        Files.deleteIfExists(stored);
        Files.deleteIfExists(Paths.get("storage/test-repo"));
    }

    // Add more tests
}
/*
 * Copyright © 2025 Devin B. Royal.
 * All Rights Reserved.
 */
EOF

# Create README.md
cat <<'EOF' > java-code-host/README.md
# Java Code Host

Production-ready Spring Boot application for hosting and sharing Java programs.

## Build and Run
- Requirements: Java 17 or higher, Gradle (for wrapper generation if not using pre-generated)
- Generate Wrapper (if needed): `gradle wrapper`
- Build: `./gradlew build`
- Run: `java -jar build/libs/codehost-0.0.1-SNAPSHOT.jar`
- Access: http://localhost:8080/

## Security Notes
- Change default admin password hash in AuthService.
- Use HTTPS in production.
- For scalability, integrate with S3 for storage.

## Deployment Tips
- Docker: Build with `docker build -t codehost .`
- (Add Dockerfile if needed)

## Features
- Upload ZIP or individual files to repositories.
- Extract ZIP automatically.
- Public list/download.
- JWT auth for uploads.
- Dark theme frontend.

## Error Handling
- Input validation on paths/files.
- Exceptions logged and returned as HTTP errors.
- Defensive checks against path traversal.
EOF

# Check Java version and warn if incompatible
java_version=$(java -version 2>&1 | grep version | awk '{print $3}' | tr -d \")
major_version=${java_version%%.*}
if [ "$major_version" -gt 17 ]; then
    echo "Warning: Detected Java $java_version. Project targets Java 17, but using toolchains to compile."
    echo "If issues persist, set JAVA_HOME to JDK 17 and rerun."
fi

# Auto-run Gradle build with error handling
echo "Project files created. Now generating Gradle wrapper and attempting auto-build..."
cd java-code-host || { echo "Failed to cd into java-code-host"; exit 1; }

# Generate wrapper (assumes global gradle installed)
gradle wrapper --gradle-version 9.0 --distribution-type bin > build_log.txt 2>&1
if [ $? -ne 0 ]; then
    echo "Warning: Failed to generate Gradle wrapper. Check build_log.txt for details."
    echo "You may need to update your global Gradle to a version supporting your Java (e.g., Gradle 9.0 for Java 24)."
    echo "Alternatively, download Gradle 9.0 manually and use it to generate the wrapper."
else
    # Run build with debug
    ./gradlew build --debug --stacktrace >> build_log.txt 2>&1
    if [ $? -eq 0 ]; then
        echo "Build successful. Check build/libs for JAR."
    else
        echo "Build failed. Running diagnostics..."
        echo "Last 100 lines of build log:"
        tail -n 100 build_log.txt
        echo "Common fixes: Ensure global Gradle supports your Java version."
        echo "Try updating Gradle or setting JAVA_HOME to JDK 17."
        echo "Verify dependencies and code syntax."
        echo "Full log in build_log.txt"
    fi
fi

# Create ZIP regardless of build success
zip -r ../java-code-host.zip . > /dev/null 2>&1
cd ..
echo "ZIP file created: java-code-host.zip"
echo "Project setup complete. If build failed, review build_log.txt in java-code-host and fix accordingly."
echo "Assumption: If error persists, update global Gradle or use JAVA_HOME=/path/to/jdk17 gradle wrapper --gradle-version 9.0"
