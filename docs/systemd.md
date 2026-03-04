# nexo_p2p Chat Daemon (systemd)

Example `systemd` unit for running `nexo_p2p chat` in daemon mode.

```ini
[Unit]
Description=NEXO P2P Chat Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nexo
Group=nexo
WorkingDirectory=/opt/nexo-2026
ExecStart=/opt/nexo-2026/target/release/nexo_p2p chat --bind 0.0.0.0:9001 --peer 10.0.0.12:9001 --sender node_a --db /var/lib/nexo/p2p.db --daemon
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/nexo
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nexo-p2p.service
sudo systemctl status nexo-p2p.service
```
