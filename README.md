# Xena Live India — Render Fixed Server

This package is the **server-only deployment package** for Render. It deliberately contains a root `Dockerfile`, root `package.json`, and root `render.yaml` so Render does not mis-detect the project as Go.

## Deploy on Render

1. Create a **new Web Service** from the repository containing this package.
2. Select **Docker** as the runtime.
3. If using the Blueprint, use the included `render.yaml`.
4. Do not set a Go build command.
5. After deployment, open `/health`. It should return JSON with `ok: true`.

## Required for full production features

The core server starts without third-party credentials. Google/Facebook OAuth, Google Play purchase verification, and TURN-based WebRTC require their corresponding environment variables from `.env.example`.

The default data store is a JSON file. On ephemeral hosting it is not a durable production database; use a persistent database/storage before real users or paid transactions.

## Android app

The Android APK must be built with the final HTTPS server URL. The current Android source uses `xenaServerUrl` at build time; hosting the server alone does not rewrite an already-built APK.
