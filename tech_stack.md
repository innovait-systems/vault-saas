# Vault SaaS — Tech Stack 🚀

This document outlines the modern, secure technologies used in the Vault SaaS platform.

---

### 📱 Frontend (Web Application)
*   **Core**: HTML5, Vanilla JavaScript (ES6+), and CSS3.
*   **Build Tool**: [Vite](https://vitejs.dev/) (Used for development and production bundling).
*   **Cryptography**: [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) (Standard browser API for **AES-256-GCM** encryption and **PBKDF2** key derivation).
*   **Typography**: [Outfit](https://fonts.google.com/specimen/Outfit) and [DM Mono](https://fonts.google.com/specimen/DM+Mono) via Google Fonts.
*   **Design**: Modern Dark-mode UI with custom CSS variables and glassmorphism.

### ⚙️ Backend (API Layer)
*   **Runtime**: [Node.js](https://nodejs.org/) (Version 20+).
*   **Framework**: [Express.js](https://expressjs.com/).
*   **Database**: [PostgreSQL](https://www.postgresql.org/) (Primary data store for users and encrypted credentials).
*   **Authentication**: [JWT (JSON Web Tokens)](https://jwt.io/) with dual-token (Access/Refresh) strategy.
*   **Security Stack**:
    *   `bcryptjs`: Secure hashing for login passwords.
    *   `otpauth`: Implementation of TOTP (Time-based One-Time Password) for Authenticator apps.
    *   `helmet`: Protection against common web vulnerabilities via HTTP headers.
    *   `express-rate-limit`: Prevents brute-force attacks on sensitive endpoints.
    *   `cors`: Configured for secure cross-origin resource sharing.
*   **Communication**: [Nodemailer](https://nodemailer.com/) for SMTP integration.

### 🐳 Infrastructure & Tooling
*   **Containerization**: [Docker](https://www.docker.com/) and **Docker Compose** for consistent cross-platform deployment.
*   **Web Server**: [Nginx](https://www.nginx.com/) (Serving the static frontend and acting as a reverse proxy).
*   **Development Utilities**:
    *   `Nodemon`: Automatic server restarts during local development.
    *   `Mailpit`: Local SMTP testing server to capture and preview outbound emails.
    *   `Docker Health Checks`: Ensures database readiness before API startup.

---

### 🛡 Security Philosophy
*   **Zero-Knowledge Architecture**: The master password remains strictly in the user's browser; the server never sees it.
*   **Encrypted-at-Rest**: Credentials are encrypted client-side *before* being transmitted to the backend.
*   **Modern Encryption**: Utilizes standard, audited cryptographic algorithms (AES-256-GCM).
