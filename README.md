# OweTogether

A self-hosted, mobile-friendly progressive web app for recording money owed between people. GBP only in this version. No payments are processed.

## What is included

- Google sign-up and sign-in: the first successful Google login creates an account.
- Connect existing users by sharing a private connection code, then choose them from a list.
- Record a date, amount, description, and who owes whom.
- The other person confirms or rejects an entry. Only confirmed entries affect balances.
- The creditor marks an accepted entry settled after receiving payment.
- Pending entries can be cancelled by their creator. Accepted and settled records are retained, not silently edited or deleted.
- Personal balances, search, filters, and JSON export including action history.
- Persistent SQLite storage in a Docker named volume.
- Installable PWA with manifest, PNG icons, service worker, and offline notice. Financial data is NOT cached offline; creating or viewing entries requires a connection.
- Dockerfile, Portainer Compose stack, GitHub Actions container build, and access-control tests.

The interactive Canvas preview is a separate browser-only demonstration. This repository is the actual server application. The deployed app starts empty, without demo users or debts.

## 1. Google setup

Create a Google Cloud project. Configure the OAuth consent screen / Google Auth Platform branding and audience. Create an OAuth client with application type **Web application**.

Register this exact authorised redirect URI, replacing the example domain with your own:

`https://owe.example.com/auth/callback`

The app requests only `openid email profile`. Save the client ID and client secret for Portainer. If your consent configuration is in testing, add your intended users as test users where required. Before wider use, complete Google's publishing and verification requirements applicable to your configuration. No Google API key, service account, or Firebase project is needed.

Official references:
- https://developers.google.com/identity/openid-connect/openid-connect
- https://docs.authlib.org/en/latest/oauth2/client/web/flask.html

## 2. Push to GitHub and build the image

1. Extract this ZIP and upload the CONTENTS of the `owetogether` folder to the root of a GitHub repository. Include `.github/workflows/docker.yml` (hidden folders must be included).
2. Use a branch named `main`, or change the workflow branch filter.
3. Enable GitHub Actions and allow package publishing for this repository.
4. Push to main. The workflow runs the included tests and publishes AMD64 and ARM64 images to GitHub Container Registry (GHCR).
5. Wait for the workflow to finish successfully. The image is `ghcr.io/<lowercase-owner>/<lowercase-repository>:latest`.
6. Either make the package public, or add GHCR registry credentials in Portainer with permission to read that package. A private Git repository also requires separate read-only Git credentials when adding the stack.

Secrets are runtime settings in Portainer. Do not commit `.env` or Google credentials. GitHub Actions does not need your Google secret.

## 3. Deploy with Portainer (Docker Standalone)

1. Choose **Stacks > Add stack > Repository**.
2. Enter your repository URL, select `refs/heads/main`, and set the Compose path to `compose.yaml`.
3. Add the variables below in Portainer, using `.env.example` as a template.
4. Deploy the stack. This pulls the prebuilt image; it does not depend on Portainer building source code or supporting relative bind mounts.
5. Configure your HTTPS reverse proxy as below, then open the public URL.

| Variable | Value |
| --- | --- |
| APP_IMAGE | Your lowercase GHCR image reference, e.g. `ghcr.io/owner/repository:latest` |
| APP_URL | Public HTTPS origin with no path, e.g. `https://owe.example.com` |
| SECRET_KEY | Random secret, at least 32 characters. Generate with `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| GOOGLE_CLIENT_ID | Google web OAuth client ID |
| GOOGLE_CLIENT_SECRET | Google web OAuth client secret |
| ALLOWED_EMAILS | Optional comma-separated Google email allowlist. Blank permits any verified Google account to register. |
| APP_PORT | Default `8095` |
| BIND_ADDRESS | Default `127.0.0.1`, appropriate for a host-based reverse proxy |

Portainer reference: https://docs.portainer.io/user/docker/stacks/add

### HTTPS and your existing reverse proxy

HTTPS is required. Secure cookies and PWA installation will not work correctly over ordinary HTTP.

For Caddy running directly on the Docker host:

```caddy
owe.example.com {
    reverse_proxy 127.0.0.1:8095
}
```

Point DNS at your server and let the proxy handle certificates. Do not expose the app's HTTP port directly to the internet.

For Nginx Proxy Manager or Caddy running in Docker, `127.0.0.1` inside the proxy container is NOT the host or this app. Prefer attaching the app and proxy to the same existing Docker network. Add that external network to `compose.yaml`, attach the service to it, remove `ports`, and proxy to `owetogether:8000`. Alternatively bind the port to a private host/LAN address reachable by the proxy and firewall it to the proxy only. Keep `APP_URL` set to the public HTTPS origin.

The callback uses the configured APP_URL rather than trusting forwarded Host headers. Keep the proxy on the same public origin; do not host the app below a subpath.

## 4. First use

1. Each person chooses Continue with Google. The first login creates their account.
2. One person shares their connection code privately. The other pastes it into Connect person.
3. Both people now appear in each other's person selector. No global user directory is exposed.
4. Add an entry. Choose They owe me or I owe them, then the person, date, amount and description.
5. The other person confirms or rejects the entry. Until confirmed it is pending and excluded from balances.
6. Once paid, the creditor chooses Mark settled. This records a status, not an actual transfer of money.
7. Use Install app if offered. On iPhone/iPad use the browser's Add to Home Screen action where supported. Installation behaviour depends on browser and platform.

Treat connection codes as private invitations. Resetting a code prevents future use of the old code but does not remove existing connections. An open registration does not reveal other users or their debts. For a small private deployment, set ALLOWED_EMAILS before inviting people.

## Updates and persistence

A push to main builds a new image. In Portainer update the stack and choose to re-pull the image and redeploy after the build succeeds. A new image alone does not guarantee a running container is updated. For reproducible releases, use the commit-SHA image tag published by the workflow instead of `latest`.

The `owe_data` named volume survives container recreation. Do not remove the volume or change the stack name without migrating data. SQLite is suitable for a small, single-server deployment; do not run multiple replicas across hosts or mount the database over a network filesystem.

## Backups and restore

Back up the complete named volume regularly and before updates. The simplest consistent backup is to stop the app, archive the volume contents (including any SQLite WAL files), and start it again. Store encrypted backups off-host and test restoring them. The per-user JSON export is not a full database backup.

To restore, stop the app, restore the volume files, preserve ownership UID/GID 10001, and restart. Keep SECRET_KEY stable across normal updates; changing it signs everyone out.

## Local build / tests

```sh
cp .env.example .env
# Edit .env with real values and a public HTTPS origin first.
docker compose -f compose.yaml -f compose.local.yaml up -d --build
```

For tests with Python 3.12:

```sh
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Tests use a temporary database and test-only sessions. They cover anonymous access, CSRF, request origin, contact visibility, amount validation, confirmation, settlement permissions, and isolation from unrelated users. They do not test a live Google login or a live Docker/Portainer deployment. Run the included workflow and complete a two-account end-to-end check before real use.

## Security and scope

The server uses Google OIDC through Authlib, verified Google email, signed secure HTTP-only SameSite cookies, CSRF tokens plus Origin checks for mutations, parameterised SQL, participant-only record access, integer pence, an audit table, and security headers. Google access tokens are not persisted. Browser storage is not used for account data. The app is a starter implementation, not an independently audited security product.

Before exposing broadly: review dependency updates, configure reverse-proxy rate limiting, monitor logs, define privacy/retention and account deletion processes, secure Portainer/GitHub/Google admin access, and test backup recovery. Account deletion, connection removal, partial payments, notifications, multi-currency, and debt disputes beyond reject/confirm are not included. The audit table is application history, not tamper-proof against the server administrator. Authentication does not prove that a claimed debt is valid.

## Troubleshooting

- **redirect_uri_mismatch:** APP_URL + `/auth/callback` must exactly match the registered Google redirect URI.
- **Repeated login / session expired:** use HTTPS, keep SECRET_KEY stable, and use the same hostname throughout.
- **Image pull denied:** check the lowercase image name, package visibility, and Portainer registry credentials.
- **Cannot select a person:** they must sign in first and connect using a code.
- **Proxy returns 502:** check the app health and Docker networking; a container's localhost is not the Docker host.
- **Permission denied on database:** volume contents must be writable by UID/GID 10001.
