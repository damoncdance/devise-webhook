"""
webhook_listener.py

Purpose:
  FastAPI webhook listener for OpenPhone and Instantly.ai events.
  Receives call/text/email events, looks up the matching Contact and Property
  in Airtable, and creates Interactions records.

Deployable to Railway.app — see Procfile and requirements.txt in project root.

Endpoints:
  POST /webhook/openphone  — call.completed, message.received,
                             call.transcript.completed, call.summary.completed
  POST /webhook/instantly  — email_sent, email_opened, email_replied, email_bounced, unsubscribed
  GET  /health             — Railway health check

Environment variables (never hardcode):
  AIRTABLE_API_KEY      — Airtable personal access token
  AIRTABLE_BASE_ID      — Airtable base ID (appXXXXXXXXXXXXXX)
  OPENPHONE_SECRET      — HMAC-SHA256 secret for OpenPhone webhook verification
  INSTANTLY_SECRET      — Shared secret for Instantly webhook verification

Local dev: copy .env.example to .env and fill in values.

Run locally:
  uvicorn webhook_listener:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

load_dotenv()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
AIRTABLE_API_KEY = os.environ.get("AIRTABLE_API_KEY", "")
AIRTABLE_BASE_ID = os.environ.get("AIRTABLE_BASE_ID", "")
OPENPHONE_SECRET = os.environ.get("OPENPHONE_SECRET", "")
INSTANTLY_SECRET = os.environ.get("INSTANTLY_SECRET", "")

AIRTABLE_BASE_URL = "https://api.airtable.com/v0"
CONTACTS_TABLE = "Contacts"
PROPERTIES_TABLE = "Properties"
INTERACTIONS_TABLE = "Interactions"

# Instantly.ai V2 webhook signature header.
# Confirmed from Instantly developer docs (https://developer.instantly.ai/webhooks):
# The header used for webhook verification is "X-Instantly-Webhook-Secret".
# If Instantly updates their header name, change this constant only.
INSTANTLY_SIGNATURE_HEADER = "X-Instantly-Webhook-Secret"

# OpenPhone uses HMAC-SHA256 — header: "X-OpenPhone-Signature"
# Ref: https://www.openphone.com/docs/api-reference/webhooks
OPENPHONE_SIGNATURE_HEADER = "X-OpenPhone-Signature"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("webhook_listener")

app = FastAPI(title="Devise Webhook Listener", version="1.0.0")


# ---------------------------------------------------------------------------
# Airtable helpers
# ---------------------------------------------------------------------------

def _airtable_headers() -> dict:
    return {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }


def _airtable_search(table: str, formula: str) -> list[dict]:
    """Search an Airtable table with a formula filter. Returns list of records."""
    url = f"{AIRTABLE_BASE_URL}/{AIRTABLE_BASE_ID}/{table}"
    params = {"filterByFormula": formula}
    resp = requests.get(url, headers=_airtable_headers(), params=params, timeout=10)
    resp.raise_for_status()
    return resp.json().get("records", [])


def _airtable_create(table: str, fields: dict) -> dict:
    """Create a single record in an Airtable table."""
    url = f"{AIRTABLE_BASE_URL}/{AIRTABLE_BASE_ID}/{table}"
    payload = {"fields": fields, "typecast": True}
    resp = requests.post(url, headers=_airtable_headers(), json=payload, timeout=10)
    resp.raise_for_status()
    return resp.json()


def find_contact_by_phone(phone: str) -> dict | None:
    """Look up a Contact record by matching any of the three phone fields."""
    # Normalize: strip non-digits, compare last 10 digits
    digits = "".join(c for c in phone if c.isdigit())[-10:]
    if not digits:
        return None
    # Airtable formula: search all three phone fields
    formula = (
        f'OR('
        f'RIGHT(SUBSTITUTE({{Phone 1}},"-",""),10)="{digits}",'
        f'RIGHT(SUBSTITUTE({{Phone 2}},"-",""),10)="{digits}",'
        f'RIGHT(SUBSTITUTE({{Phone 3}},"-",""),10)="{digits}"'
        f')'
    )
    records = _airtable_search(CONTACTS_TABLE, formula)
    return records[0] if records else None


def find_contact_by_email(email: str) -> dict | None:
    """Look up a Contact record by Email 1."""
    email = email.strip().lower()
    formula = f'LOWER({{Email 1}})="{email}"'
    records = _airtable_search(CONTACTS_TABLE, formula)
    return records[0] if records else None


def get_linked_property(contact_record: dict) -> dict | None:
    """Get the first linked Property record from a Contact."""
    linked = contact_record.get("fields", {}).get("Properties", [])
    if not linked:
        return None
    prop_id = linked[0] if isinstance(linked[0], str) else linked[0].get("id")
    url = f"{AIRTABLE_BASE_URL}/{AIRTABLE_BASE_ID}/{PROPERTIES_TABLE}/{prop_id}"
    resp = requests.get(url, headers=_airtable_headers(), timeout=10)
    if resp.status_code == 200:
        return resp.json()
    return None


def create_interaction(fields: dict) -> dict:
    """Create an Interactions record."""
    return _airtable_create(INTERACTIONS_TABLE, fields)


def _airtable_update(table: str, record_id: str, fields: dict) -> dict:
    """Update a single record in an Airtable table (PATCH — merge, not replace)."""
    url = f"{AIRTABLE_BASE_URL}/{AIRTABLE_BASE_ID}/{table}/{record_id}"
    payload = {"fields": fields}
    resp = requests.patch(url, headers=_airtable_headers(), json=payload, timeout=10)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

def verify_openphone_signature(body: bytes, signature: str) -> bool:
    """Verify OpenPhone HMAC-SHA256 webhook signature."""
    if not OPENPHONE_SECRET:
        logger.warning("OPENPHONE_SECRET not set — skipping signature verification")
        return True
    expected = hmac.new(
        OPENPHONE_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def verify_instantly_secret(provided: str) -> bool:
    """Verify Instantly shared secret token."""
    if not INSTANTLY_SECRET:
        logger.warning("INSTANTLY_SECRET not set — skipping verification")
        return True
    return hmac.compare_digest(INSTANTLY_SECRET, provided)


# ---------------------------------------------------------------------------
# OpenPhone event mapping
# ---------------------------------------------------------------------------

_OPENPHONE_OUTCOME_MAP = {
    "answered": "Connected",
    "completed": "Connected",
    "voicemail": "Voicemail",
    "missed": "No Answer",
    "no-answer": "No Answer",
    "busy": "No Answer",
    "failed": "No Answer",
    "received": "Replied",   # for messages
}

_OPENPHONE_DIRECTION_MAP = {
    "incoming": "Inbound",
    "outgoing": "Outbound",
    "inbound": "Inbound",
    "outbound": "Outbound",
}


def _parse_openphone_event(event_type: str, payload: dict) -> dict | None:
    """
    Parse an OpenPhone event payload into an Interactions field dict.
    Returns None if event should be ignored.

    Expected payload shape (call.completed):
    {
      "type": "call.completed",
      "data": {
        "object": {
          "direction": "inbound|outbound",
          "from": "+17085551234",
          "to": "+17089250820",
          "status": "completed|voicemail|no-answer",
          "duration": 142,
          "createdAt": "2026-03-24T18:30:00Z",
          "recording": {"url": "https://..."},
          "summary": "Caller asked about selling..."
        }
      }
    }
    """
    data = payload.get("data", {}).get("object", {})
    if not data:
        return None

    direction_raw = str(data.get("direction", "")).lower()
    status_raw = str(data.get("status", "")).lower()
    ts = data.get("createdAt") or data.get("completedAt") or datetime.now(timezone.utc).isoformat()

    # Extract callId from payload root (call-related events)
    call_id = payload.get("data", {}).get("object", {}).get("callId") or ""

    if event_type == "call.completed":
        phone = data.get("from") if direction_raw == "inbound" else data.get("to")
        return {
            "type": "Call",
            "direction": direction_raw,
            "phone": phone,
            "outcome": _OPENPHONE_OUTCOME_MAP.get(status_raw, "Connected"),
            "duration": data.get("duration"),
            "recording_url": (data.get("recording") or {}).get("url"),
            "ai_summary": data.get("summary"),
            "timestamp": ts,
            "openphone_call_id": call_id,
        }

    if event_type == "message.received":
        phone = data.get("from")
        return {
            "type": "Text",
            "direction": "Inbound",
            "phone": phone,
            "outcome": "Replied",
            "timestamp": ts,
        }

    return None


# ---------------------------------------------------------------------------
# Instantly event mapping
# ---------------------------------------------------------------------------

_INSTANTLY_OUTCOME_MAP = {
    "email_sent": "Sent",
    "email_opened": "Opened",
    "email_replied": "Replied",
    "email_bounced": "Bounced",
    "unsubscribed": "Unsubscribed",
}

_INSTANTLY_DIRECTION_MAP = {
    "email_sent": "Outbound",
    "email_opened": "Outbound",
    "email_replied": "Inbound",
    "email_bounced": "Outbound",
    "unsubscribed": "Inbound",
}


def _parse_instantly_event(event_type: str, payload: dict) -> dict | None:
    """
    Parse an Instantly V2 event payload.

    Expected payload shape:
    {
      "event_type": "email_replied",
      "timestamp": "2026-03-24T20:15:00Z",
      "data": {
        "lead_email": "owner@example.com",
        "subject": "Re: Regarding your property...",
        "campaign_id": "...",
        "campaign_name": "...",
        "sequence_tier": "Tier4-Full"
      }
    }
    """
    data = payload.get("data", {})
    email = data.get("lead_email") or data.get("email")
    ts = payload.get("timestamp") or datetime.now(timezone.utc).isoformat()

    if not email or event_type not in _INSTANTLY_OUTCOME_MAP:
        return None

    return {
        "email": email,
        "type": "Email",
        "direction": _INSTANTLY_DIRECTION_MAP[event_type],
        "outcome": _INSTANTLY_OUTCOME_MAP[event_type],
        "subject": data.get("subject"),
        "sequence_tier": data.get("sequence_tier") or data.get("campaign_name"),
        "timestamp": ts,
    }


# ---------------------------------------------------------------------------
# Shared interaction logger
# ---------------------------------------------------------------------------

def _log_interaction(
    lookup_type: str,
    lookup_value: str,
    event_fields: dict,
    source: str,
) -> JSONResponse:
    """
    Find contact + property, create Interactions record.
    lookup_type: "phone" or "email"
    """
    # 1. Look up contact
    if lookup_type == "phone":
        contact = find_contact_by_phone(lookup_value)
    else:
        contact = find_contact_by_email(lookup_value)

    if not contact:
        logger.warning(f"No contact found for {lookup_type}={lookup_value}")
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "no_match", "reason": f"No contact for {lookup_type}={lookup_value}"},
        )

    contact_id = contact["id"]
    contact_name = contact.get("fields", {}).get("Contact Name", "")

    # 2. Look up linked property
    prop_record = get_linked_property(contact)
    prop_id = prop_record["id"] if prop_record else None
    pin = (prop_record or {}).get("fields", {}).get("PIN", "")

    # 3. Build Interactions fields
    interaction_id = f"{event_fields.get('timestamp', '')[:10]}-{pin or contact_name[:10]}"
    fields: dict[str, Any] = {
        "Interaction ID": interaction_id,
        "Link to Contact": [contact_id],
        "Type": event_fields["type"],
        "Direction": _OPENPHONE_DIRECTION_MAP.get(event_fields.get("direction", ""), event_fields.get("direction", "Outbound")),
        "Date and Time": event_fields.get("timestamp"),
        "Outcome": event_fields.get("outcome"),
        "Source": source,
        "Notes": f"Auto-logged by webhook_listener",
    }
    if prop_id:
        fields["Link to Property"] = [prop_id]
    if event_fields.get("duration"):
        fields["Duration seconds"] = event_fields["duration"]
    if event_fields.get("recording_url"):
        fields["Recording URL"] = event_fields["recording_url"]
    if event_fields.get("ai_summary"):
        fields["AI Summary"] = event_fields["ai_summary"]
    if event_fields.get("subject"):
        fields["Subject"] = event_fields["subject"]
    if event_fields.get("sequence_tier"):
        fields["Sequence Tier"] = event_fields["sequence_tier"]
    if event_fields.get("openphone_call_id"):
        fields["OpenPhone Call ID"] = event_fields["openphone_call_id"]

    try:
        record = create_interaction(fields)
        logger.info(f"Interaction created: {record['id']} for {contact_name} ({pin})")
    except Exception as exc:
        logger.error(f"Failed to create Interaction: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))

    # 4. Update Contact measurement fields based on event outcome
    try:
        _update_contact_measurement_fields(
            contact_id, contact, event_fields.get("outcome", ""), event_fields.get("timestamp", "")
        )
    except Exception as exc:
        # Non-fatal — log but don't fail the webhook
        logger.warning(f"Failed to update Contact measurement fields: {exc}")

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"status": "ok", "interaction_id": record["id"], "pin": pin},
    )


# ---------------------------------------------------------------------------
# Contact measurement field updates
# ---------------------------------------------------------------------------

def _update_contact_measurement_fields(
    contact_id: str,
    contact_record: dict,
    outcome: str,
    timestamp: str,
) -> None:
    """
    Update Contact-level measurement fields after logging an Interaction.
    Only sets fields that are relevant to the event outcome.
    Uses first-write semantics for timestamp fields (won't overwrite existing values).
    """
    existing = contact_record.get("fields", {})
    updates: dict[str, Any] = {}

    if outcome == "Sent":
        # First touch tracking
        if not existing.get("First Touched At"):
            updates["First Touched At"] = timestamp
        # Set deliverability to Delivered (may be overridden by Bounced later)
        if not existing.get("Deliverability Status"):
            updates["Deliverability Status"] = "Delivered"

    elif outcome == "Opened":
        # Increment open count
        current_count = existing.get("Open Count") or 0
        updates["Open Count"] = current_count + 1
        if not existing.get("First Opened At"):
            updates["First Opened At"] = timestamp

    elif outcome == "Replied":
        if not existing.get("First Replied At"):
            updates["First Replied At"] = timestamp
        # Set sentiment to Unclassified pending manual review
        if not existing.get("Reply Sentiment"):
            updates["Reply Sentiment"] = "Unclassified"

    elif outcome == "Bounced":
        updates["Bounce Flag"] = True
        updates["Deliverability Status"] = "Bounced"

    elif outcome == "Unsubscribed":
        updates["Unsubscribed"] = True
        updates["Unsubscribed At"] = timestamp
        updates["Deliverability Status"] = "Unsubscribed"

    if updates:
        _airtable_update(CONTACTS_TABLE, contact_id, updates)
        logger.info(f"Contact {contact_id} measurement fields updated: {list(updates.keys())}")


# ---------------------------------------------------------------------------
# OpenPhone transcript/summary handlers
# ---------------------------------------------------------------------------

def _find_interaction_by_call_id(call_id: str) -> dict | None:
    """Look up an Interaction record by OpenPhone Call ID."""
    if not call_id:
        return None
    formula = f'{{OpenPhone Call ID}}="{call_id}"'
    records = _airtable_search(INTERACTIONS_TABLE, formula)
    return records[0] if records else None


def _format_transcript(dialogue: list[dict]) -> str:
    """Convert OpenPhone dialogue array to readable transcript text."""
    lines = []
    for entry in dialogue:
        speaker = entry.get("identifier") or entry.get("userId") or "Unknown"
        content = entry.get("content", "")
        start = entry.get("start")
        ts_prefix = f"[{start:.1f}s] " if start is not None else ""
        lines.append(f"{ts_prefix}{speaker}: {content}")
    return "\n".join(lines)


def _handle_transcript_completed(payload: dict) -> JSONResponse:
    """
    Handle call.transcript.completed / callTranscript events.
    Looks up existing Interaction by callId and appends transcript data.
    """
    data = payload.get("data", {}).get("object", {})
    call_id = data.get("callId", "")
    if not call_id:
        logger.warning("Transcript event missing callId")
        return JSONResponse(status_code=200, content={"status": "ignored", "reason": "no callId"})

    now_iso = datetime.now(timezone.utc).isoformat()
    dialogue = data.get("dialogue", [])
    transcript_text = _format_transcript(dialogue) if dialogue else ""

    # Look up existing Interaction
    interaction = _find_interaction_by_call_id(call_id)

    updates: dict[str, Any] = {
        "Transcript Received At": now_iso,
    }
    if transcript_text:
        updates["Call Transcript"] = transcript_text
    if data.get("duration"):
        updates["Duration seconds"] = data["duration"]

    if interaction:
        record_id = interaction["id"]
        try:
            _airtable_update(INTERACTIONS_TABLE, record_id, updates)
            logger.info(f"Transcript appended to interaction {record_id} (callId={call_id})")
            return JSONResponse(status_code=200, content={"status": "ok", "interaction_id": record_id, "action": "updated"})
        except Exception as exc:
            logger.error(f"Failed to update Interaction with transcript: {exc}")
            raise HTTPException(status_code=500, detail=str(exc))
    else:
        logger.warning(f"No existing Interaction for callId={call_id} — creating stub record")
        updates["Interaction ID"] = f"transcript-{call_id[:20]}"
        updates["Type"] = "Call"
        updates["Source"] = "OpenPhone"
        updates["OpenPhone Call ID"] = call_id
        updates["Notes"] = "Auto-created from transcript event (call.completed not yet received)"
        updates["Date and Time"] = data.get("createdAt") or now_iso
        try:
            record = _airtable_create(INTERACTIONS_TABLE, updates)
            logger.info(f"Stub Interaction created for transcript: {record['id']} (callId={call_id})")
            return JSONResponse(status_code=200, content={"status": "ok", "interaction_id": record["id"], "action": "created_stub"})
        except Exception as exc:
            logger.error(f"Failed to create stub Interaction for transcript: {exc}")
            raise HTTPException(status_code=500, detail=str(exc))


def _handle_summary_completed(payload: dict) -> JSONResponse:
    """
    Handle call.summary.completed / callSummary events.
    Looks up existing Interaction by callId and appends summary data.
    """
    data = payload.get("data", {}).get("object", {})
    call_id = data.get("callId", "")
    if not call_id:
        logger.warning("Summary event missing callId")
        return JSONResponse(status_code=200, content={"status": "ignored", "reason": "no callId"})

    now_iso = datetime.now(timezone.utc).isoformat()
    summary_lines = data.get("summary") or []
    next_steps = data.get("nextSteps") or []
    summary_text = "\n".join(summary_lines) if isinstance(summary_lines, list) else str(summary_lines)
    next_steps_text = "\n".join(next_steps) if isinstance(next_steps, list) else str(next_steps)

    # Look up existing Interaction
    interaction = _find_interaction_by_call_id(call_id)

    updates: dict[str, Any] = {
        "Summary Received At": now_iso,
    }
    if summary_text:
        updates["Call Summary"] = summary_text
    if next_steps_text:
        updates["Call Next Steps"] = next_steps_text
    # Also write to AI Summary for backward compatibility with existing views
    if summary_text:
        updates["AI Summary"] = summary_text

    if interaction:
        record_id = interaction["id"]
        try:
            _airtable_update(INTERACTIONS_TABLE, record_id, updates)
            logger.info(f"Summary appended to interaction {record_id} (callId={call_id})")
            return JSONResponse(status_code=200, content={"status": "ok", "interaction_id": record_id, "action": "updated"})
        except Exception as exc:
            logger.error(f"Failed to update Interaction with summary: {exc}")
            raise HTTPException(status_code=500, detail=str(exc))
    else:
        logger.warning(f"No existing Interaction for callId={call_id} — creating stub record")
        updates["Interaction ID"] = f"summary-{call_id[:20]}"
        updates["Type"] = "Call"
        updates["Source"] = "OpenPhone"
        updates["OpenPhone Call ID"] = call_id
        updates["Notes"] = "Auto-created from summary event (call.completed not yet received)"
        updates["Date and Time"] = now_iso
        try:
            record = _airtable_create(INTERACTIONS_TABLE, updates)
            logger.info(f"Stub Interaction created for summary: {record['id']} (callId={call_id})")
            return JSONResponse(status_code=200, content={"status": "ok", "interaction_id": record["id"], "action": "created_stub"})
        except Exception as exc:
            logger.error(f"Failed to create stub Interaction for summary: {exc}")
            raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/webhook/openphone")
async def webhook_openphone(request: Request):
    body = await request.body()

    # Signature verification
    sig = request.headers.get(OPENPHONE_SIGNATURE_HEADER, "")
    if not verify_openphone_signature(body, sig):
        logger.warning("OpenPhone signature verification failed")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signature")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    event_type = payload.get("type", "")
    logger.info(f"OpenPhone event: {event_type}")

    # Route transcript/summary events to dedicated handlers
    # OpenPhone uses "callTranscript" or "call.transcript.completed" as the type
    if event_type in ("call.transcript.completed", "callTranscript"):
        return _handle_transcript_completed(payload)
    if event_type in ("call.summary.completed", "callSummary"):
        return _handle_summary_completed(payload)

    event_fields = _parse_openphone_event(event_type, payload)
    if not event_fields:
        return JSONResponse(status_code=200, content={"status": "ignored", "event": event_type})

    phone = event_fields.pop("phone", "")
    if not phone:
        return JSONResponse(status_code=200, content={"status": "no_phone"})

    return _log_interaction("phone", phone, event_fields, source="OpenPhone")


@app.post("/webhook/instantly")
async def webhook_instantly(request: Request):
    # Verify Instantly shared secret
    provided_secret = request.headers.get(INSTANTLY_SIGNATURE_HEADER, "")
    if not verify_instantly_secret(provided_secret):
        logger.warning("Instantly signature verification failed")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid secret")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    event_type = payload.get("event_type", "")
    logger.info(f"Instantly event: {event_type}")

    event_fields = _parse_instantly_event(event_type, payload)
    if not event_fields:
        return JSONResponse(status_code=200, content={"status": "ignored", "event": event_type})

    email = event_fields.pop("email", "")
    if not email:
        return JSONResponse(status_code=200, content={"status": "no_email"})

    return _log_interaction("email", email, event_fields, source="Instantly")
