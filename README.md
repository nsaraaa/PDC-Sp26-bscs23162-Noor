Sara Noor - BSCS23162

# PDC StudySync Resilient Distributed Systems Assignment

This repo implements Part 3 using **Problem 1: Synchronization**. The broken endpoint demonstrates a lost update anomaly, and the fixed endpoint uses **optimistic locking** with document versions.

## Architecture Flowchart

![StudySync architecture flowchart](flowchat.png)

Every API response includes the required header:

```text
X-Student-ID: BSCS23162
```

## Run the API

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

## Run the Tests

```bash
pytest -q
```

## Run the Demo Script

Start the API first, then run:

```bash
python demo_sync.py
```

If port `8000` is already busy, start Uvicorn on another port and pass it to the demo:

```bash
uvicorn main:app --reload --port 8001
BASE_URL=http://localhost:8001 python demo_sync.py
```

The demo shows:

1. `PUT /naive/docs/1` silently overwriting one concurrent edit.
2. `PUT /docs/1` rejecting the stale write with HTTP `409 Conflict`.
3. The required `X-Student-ID` middleware header.

## Main Endpoints

- `GET /docs/{doc_id}`: read a document with its current version.
- `PUT /naive/docs/{doc_id}`: broken last-write-wins update.
- `PUT /docs/{doc_id}`: fixed optimistic-locking update that requires the client's last-read version.
- `POST /docs/{doc_id}/reset`: reset demo state.
