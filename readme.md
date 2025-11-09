## HiroWire OPNsense Manager

This is a simple web application written in Rust that provides a UI for:

Generating new WireGuard client configurations (.tail, .key, .pub, .psk files).

Automatically adding/deleting those clients (peers) to an OPNsense firewall via its API.

The application is built with Actix Web (Rust backend), Tera (templating), and Tailwind CSS (frontend).

### Features

Modern UI: A clean, multi-page layout with a responsive sidebar.

Generate New Peers: Create new key pairs (private, public, preshared) and a client config file.

Add Existing Peers: Add a peer to OPNsense using their existing public key.

OPNsense API Integration: Automatically pushes new peers to your OPNsense firewall and applies the changes.

Peer Management: A "Manage Peers" page that fetches all current peers from OPNsense and allows you to delete them (i.e., "renew" clients).

File Downloads: Download the full .tail config or individual .key, .pub, and .psk files.

Containerized: Full Dockerfile support for easy production deployment.

### Configuration (.env file)

This project requires a .env file to store your OPNsense API credentials and server information. These secrets are ignored by Git (via .dockerignore) and should never be committed to source control.

To get started, copy the example file:

cp .env.example .env


Then, open the new .env file and fill in all the values:

Variable

Description

OPN_API_KEY

The API Key you generated in the OPNsense UI.

OPN_API_SECRET

The API Secret you generated in the OPNsense UI.

OPN_BASE_URL

The base URL of your OPNsense firewall (e.g., https://opnsense.my-domain.com).

WG_SERVER_ENDPOINT

The public-facing endpoint for your WireGuard server (e.g., wg.my-domain.com:51820).

WG_SERVER_PUBLIC_KEY

The public key of your OPNsense WireGuard server instance.

OPN_SERVER_UUID

The UUID of the OPNsense WireGuard Server you want to add peers to.

OPN_WG_INSTANCE_UUID

The UUID of the OPNsense WireGuard Local Instance (under VPN->WireGuard->Local). This is needed to apply changes.

### How to Run (Development)

Install Rust: If you haven't already, install the Rust toolchain.

Create .env: Copy .env.example to .env and fill in your OPNsense details (see above).

Run the app:

cargo run


Open your browser to http://127.0.0.1:8080.

### How to Run (Docker)

Install Docker: Install Docker Desktop or Docker Engine.

Create .env: Create the .env file as described above. The docker run command will pass this file into the container.

Build the image:

docker build -t wg-tool .


Run the container:

docker run -p 8080:8080 --env-file .env --rm wg-tool


-p 8080:8080: Maps your local port 8080 to the container's port 8080.

--env-file .env: Securely passes your secrets from the .env file to the app inside the container.

--rm: Deletes the container when you stop it.

wg-tool: The name you tagged the image with in the build step.

Open your browser to http://localhost:8080.

### API Endpoints

The app also provides a few simple JSON API endpoints used by the frontend:

GET /api/peers: Fetches all peers from the OPNsense server.

POST /api/delete_peer: Deletes a peer. Requires a JSON body: {"uuid": "..."}.