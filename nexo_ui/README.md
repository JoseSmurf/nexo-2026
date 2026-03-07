# NEXO UI v1 (Ruby + Sinatra)

This is the first visual layer for NEXO.

## Run locally

```bash
cd nexo_ui
ruby app.rb
```

Open in browser:

```text
http://127.0.0.1:4567
```

## Current behavior

- Real-ish status source with fallback:
  - Reads JSON state from `NEXO_UI_STATE_PATH` (or `state.json`).
  - If unavailable, tries simple SQLite read from `state.db` (`nexo_state` table).
  - If unavailable, falls back to deterministic simulated state.
- `/api/status` includes `data_source`:
  - `"real"` when state was loaded from JSON/SQLite.
  - `"fallback_simulated"` when no real state source is available.

- `/api/status` returns `state`, `seed`, `last_updated`, and `data_source`.
  State now includes event activity fields:
  - `recent_events`
  - `last_event_hash`
  - `event_type`
  - `event_timestamp`
  - `event_origin`
  - `event_channel`

- `recent_events` is a short timeline (up to 5 entries), most recent first:
  - `hash`
  - `type`
  - `timestamp`
  - `origin`
  - `channel`
- `/api/health` returns:
  - `ui_status`
  - `data_source`
  - `source_type` (`file` | `sqlite` | `fallback` | `demo`)
  - `adapter_status`
  - `last_updated`
  - `seed`
- `/api/health` failures (network/server error) are rendered as `ui_status: "unavailable"` by the UI policy banner and Integrity card.
- `/api/simulate` is kept as **demo mode** and returns `data_source: "fallback_simulated"`.

## Simulated state fields

- `system_status`
- `peers_count`
- `relay_status`
- `ai_last_insight`
- `recent_event_hash`
- `last_sync`
- `last_event_hash`
- `event_type`
- `event_timestamp`
- `event_origin`
- `event_channel`
- `recent_ai_insights` (até 3 itens: text, timestamp, type, origin)
- `recent_events`
