# Bitkey FIDO2 Passkey Demo

This demo application demonstrates FIDO2 passkey authentication for the Bitkey wallet system. It consists of a server component for handling FIDO2 operations and a client component for user interaction.

## Prerequisites

- Node.js 16+ and npm

## Setup

### Server Setup

1. Navigate to the server directory:
   ```
   cd server
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Start the server:
   ```
   npm start
   ```

The server will run on http://localhost:3000.

### Client Setup

1. Navigate to the client directory:
   ```
   cd client
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Start the client:
   ```
   npm start
   ```

The client will run on http://localhost:8080.

## Usage

1. Open your browser and navigate to http://localhost:8080
2. Register a new user by entering a username and clicking "Register with Passkey"
3. Follow the browser prompts to create a passkey
4. After registration, authenticate using the same username by clicking "Authenticate with Passkey"
5. Follow the browser prompts to authenticate with your passkey

## Features

- FIDO2 passkey registration
- FIDO2 passkey authentication
- User management (in-memory storage)
- WebAuthn API integration

## Implementation Notes

- This demo uses in-memory storage and is not suitable for production use
- The server uses SimpleWebAuthn for FIDO2 operations
- The client uses the WebAuthn API via SimpleWebAuthn browser library
- This demo is intended to showcase the FIDO2 authentication flow that replaces hardware wallet authentication in the Bitkey system

## Testing Notes

- The demo works best in Chrome, Edge, or Safari
- Make sure to run both server and client components
- For testing on mobile devices, use a secure context (HTTPS) or enable WebAuthn on non-secure contexts in your browser settings
