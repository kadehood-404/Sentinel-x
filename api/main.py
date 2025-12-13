from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from uuid import uuid4
from datetime import datetime
import json

app = FastAPI(title="Sentinel-X")

@app.post("/events/ingest")
def ingest_event(event: dict):
    event["event_id"] = str(uuid4())
    event["timestamp"] = datetime.utcnow().isoformat()

    with open("storage/events.log", "a") as f:
        f.write(json.dumps(event) + "\n")

    return {"status": "accepted", "event_id": event["event_id"]}
