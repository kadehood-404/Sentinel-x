Sentinel-X

Sentinel-X is an open-source intrusion detection framework focused on correlation, transparency, and evidence-based security analysis.

It is designed to observe system and network behavior, record events in a normalized format, and highlight patterns that may warrant investigation — not to declare compromise by default.

This project favors signal over noise, explainability over theatrics, and facts over fear.

Why Sentinel-X Exists

Modern systems generate enormous amounts of activity. Most of it is normal. Some of it is misconfiguration. A small fraction may be malicious.

Sentinel-X exists to answer one question clearly:

“What actually happened?”

Not:

“You’re hacked”

“Someone is watching you”

“Everything is on fire”

Just observable, reviewable data.

What Sentinel-X Is

A correlation-first IDS

A forensic-friendly event recorder

A transparent security observability tool

Suitable for home labs, small networks, and research

What Sentinel-X Is Not

Not antivirus software

Not a replacement for EDR

Not a magic breach detector

Not a tool for confirming suspicions without evidence

If Sentinel-X shows nothing suspicious, that is a valid and valuable result.

Core Principles

Observe before judging

Correlate before alerting

Explain every detection

Default to safety and restraint

Never amplify fear

Architecture Overview

Event Ingest

Network, host, and application events

Normalized into a canonical schema

Detection Engines

Signature-based

Heuristic-based

Anomaly-based (baseline deviation)

Correlation Engine

Time-window analysis

Multi-stage behavior detection

Incident generation with confidence scoring

Response (Optional)

Notification and tagging by default

Enforcement disabled unless explicitly enabled

Event Model

All data in Sentinel-X conforms to a documented event schema.

This ensures:

No hidden logic

No opaque decisions

No unverifiable claims

See: docs/event_schema.md

Operating Modes

Observe Only (Default)

Logs events

Detects patterns

No automated actions

Enforce (Advanced)

Optional responses such as blocking or quarantining

Intended for experienced operators only

Use Cases

Establishing a baseline of normal activity

Investigating suspected anomalies calmly and methodically

Learning how intrusion detection actually works

Demonstrating when systems are behaving normally

Ethical Use Statement

Sentinel-X is intended for defensive, educational, and diagnostic purposes.

It should not be used to:

Monitor people without consent

Validate paranoia

Harass or surveil others

Security tools should reduce harm, not increase it.

Status

This project is under active development.

Early versions prioritize:

Correctness

Transparency

Documentation

License

MIT License. See LICENSE.

A Note on Results

Seeing no incidents is a success.

Seeing explainable incidents is progress.

Seeing uncertain results is a prompt to gather more data, not jump to conclusions.

Sentinel-X
Observe. Correlate. Understand.
