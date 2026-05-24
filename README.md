# Sentinel-X

Sentinel-X is an open-source intrusion detection framework focused on correlation, transparency, and evidence-based security analysis.

It is designed to observe system and network behavior, record events in a normalized format, and highlight patterns that may warrant investigation — not to declare compromise by default.

This project favors signal over noise, explainability over theatrics, and facts over fear.

> ⚠️ **DEVELOPMENT STATUS: ACTIVE R&D**
> Core multi-threaded data ingestion pipelines and log-rotation loops are operational. Current sprint focus: Refining the parsing boundaries and telemetry normalization layers to maintain low-latency tracking under localized data spikes.

---

## Why Sentinel-X Exists

Modern systems generate enormous amounts of activity. Most of it is normal. Some of it is misconfiguration. A small fraction may be malicious.

Sentinel-X exists to answer one question clearly:
> **“What actually happened?”**

**It does not scream:**
* *“You’re hacked”*
* *“Someone is watching you”*
* *“Everything is on fire”*

It provides just observable, reviewable data. If Sentinel-X shows nothing suspicious, that is a valid and valuable result.

---

## Core Pillars

* **A Correlation-First IDS:** Moves beyond isolated alert triggers to map relationships across disparate system events.
* **A Forensic-Friendly Event Recorder:** Normalizes raw telemetry into immutable, structured historical logs.
* **A Transparent Security Observability Tool:** Suitable for home labs, small networks, and infrastructure research.

**What Sentinel-X Is Not:**
* Not antivirus software or an EDR replacement.
* Not a magic breach detector.
* Not a tool for confirming suspicions without evidence.

---

## Technical Architecture & Ingestion Pipeline

To maintain this zero-theatrics posture under load, the framework operates as a decoupled, multi-threaded state engine. This producer-consumer layout ensures intensive heuristic evaluation never blocks the live incoming telemetry capture.

[Network Interfaces] ---> (Ingestion Thread 01) ---\
[System Event Logs]  ---> (Ingestion Thread 02) ----+---> [Thread-Safe Queue] ---> [Correlation Engine] ---> [Normalized Logs]
[Hardware Telem]     ---> (Ingestion Thread 03) ---/

1. **Ingestion Layer (Producers):** Isolated, light-weight worker threads poll system sockets, log pools, or hardware telemetry interfaces.
2. **The Ingestion Queue:** A thread-safe FIFO buffer aggregates raw event payloads, isolating the ingestion boundary from down-stream processing lag.
3. **The Correlation Engine (Consumer):** Decoupled analyzer loops pull telemetry from the queue, evaluate patterns against structural invariants, and write to clean forensic logs.

---

## Operational Roadmap

- [x] Asynchronous multi-threaded worker pipeline infrastructure
- [x] Fail-safe, zero-loss log-rotation mechanism
- [ ] Implement extensible signature-matching modules for localized environment anomalies
- [ ] Standardize automated integration test suites for malformed network frames

---

## Defensive Posture

Sentinel-X assumes a zero-trust architecture regarding input data. All data structures passing through the ingestion queue are treated as potentially hostile or malformed. By executing structural validation inside isolated consumer threads, any malformation designed to cause a script panic is safely contained, keeping the core tracking framework completely online.
