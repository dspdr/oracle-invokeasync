# oracle-invokeasync
Test Client for Fusion AI Orchestrator **/invokeAsync**

This repo contains a small **Python CLI** that can:

1. Get an OAuth2 access token from **IDCS** (client credentials)
2. Call the Fusion AI Orchestrator **/invokeAsync** endpoint
3. Optionally poll **/status/{jobId}** until the job reaches a terminal state

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

If you see `externally-managed-environment` when running `pip install`, it means you’re installing outside a venv. Activate the venv (`source .venv/bin/activate`) and try again.

Edit `.env` and fill in:

- `TOKEN_URL` (e.g. `https://<idcs-host>/oauth2/v1/token`)
- `CLIENT_ID`
- `CLIENT_SECRET`
- `SCOPE` (e.g. `urn:opc:resource:fusion:<POD>:fusion-ai/`)
- `FUSION_BASE_URL` (e.g. `https://<pod>.fusionapps...`)
- `WORKFLOW_CODE` (your workflow / agent team code)

> Note: `.env` is ignored by git via `.gitignore`. Do not commit secrets.

## Usage

### Fetch token (prints token metadata; redacts the actual access_token by default)

```bash
python client.py token
```

To also print the token:

```bash
python client.py token --show-token
```

### Invoke async

```bash
python client.py invoke --message "My name is John"
```

### Invoke and poll status until completion

```bash
python client.py invoke --message "My name is John" --poll --interval 2 --timeout 180
```

## Endpoints used

The client calls:

- Token: `POST $TOKEN_URL` with `grant_type=client_credentials` and `scope=$SCOPE` using **Basic Auth** (`CLIENT_ID:CLIENT_SECRET`).
- Invoke: `POST $FUSION_BASE_URL/api/fusion-ai/orchestrator/agent/v2/$WORKFLOW_CODE/invokeAsync`
- Status (tries both):
  1. `GET .../agent/v2/$WORKFLOW_CODE/status/{jobId}`
  2. `GET .../agent/v2/status/{jobId}`

If your status endpoint differs, tell me the exact path and I’ll adjust the client.
