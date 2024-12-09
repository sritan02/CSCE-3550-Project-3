# CSCE-3550-Project-3
Project 3: Enhancing JWKS Server Security and Functionality

Overview

Project 3 focuses on upgrading our JWKS server by integrating AES encryption for private keys and introducing new user management features. The enhancements include secure storage of encrypted keys, a robust user registration process, detailed logging of authentication requests, and an optional rate limiter to prevent abuse. This project aims to improve security, manageability, and resilience against cyber threats, ensuring that user data and authentication processes meet high security standards.

Features

AES Encryption: Securely encrypt private keys using AES with keys sourced from environment variables.
User Registration: Implement a POST:/register endpoint for user sign-ups, generating and hashing passwords securely.
Authentication Logging: Track authentication attempts in a new auth_logs table, capturing request details for security monitoring.
Rate Limiting (Optional): Control request frequency to the POST:/auth endpoint to mitigate potential DoS attacks.
