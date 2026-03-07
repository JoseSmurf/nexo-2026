# NEXO UI v1 (Ruby + Sinatra)

This is the first visual layer for NEXO. It is intentionally minimal and uses
simulated state only.

## Run locally

```bash
cd nexo_ui
# Install Sinatra if needed
# gem install --user-install sinatra
ruby app.rb
```

Open in browser:

```text
http://127.0.0.1:4567
```

## Files

- `app.rb` - Sinatra app with `/` route and simple motion seed from state hash
- `views/index.erb` - dashboard layout and cards
- `public/styles.css` - dragon-scale inspired dark interface
- `README.md` - this file

## State fields currently mocked in app.rb

- `system_status`
- `peers_count`
- `relay_status`
- `ai_last_insight`
- `recent_event_hash`
- `last_sync`

The motion effect is generated from a SHA-256 digest of these state fields and can
be replaced by a future `core_adapter` connector without changing the layout.
