"""Audit logging module for SecOps Tool - SIEM integration."""
import os
import json
import time
import socket
import getpass
from datetime import datetime
from typing import Optional, Dict, Any


class AuditLogger:
    """Logs scan activities for SIEM/Splunk/Datadog integration."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", False)
        self.log_file = self.config.get("log_file", "/var/log/secops-audit.log")
        self.syslog_server = self.config.get("syslog_server")
        self.splunk_url = self.config.get("splunk_url")
        self.splunk_token = self.config.get("splunk_token")

    def log_scan(self, target: str, findings_count: int, duration_ms: int,
                 scanners_used: list, fail_on: Optional[str] = None, exit_code: int = 0):
        """Log a scan event."""
        if not self.enabled:
            return

        payload = self._build_payload(target, findings_count, duration_ms, scanners_used, fail_on, exit_code)
        self._write_log(payload)

    def _build_payload(self, target: str, findings_count: int, duration_ms: int,
                       scanners_used: list, fail_on: Optional[str], exit_code: int) -> Dict[str, Any]:
        """Build structured log payload."""
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "secops_scan",
            "host": socket.gethostname(),
            "user": getpass.getuser(),
            "target": os.path.abspath(target),
            "target_basename": os.path.basename(target),
            "findings_count": findings_count,
            "duration_ms": duration_ms,
            "scanners_used": scanners_used,
            "fail_on": fail_on,
            "exit_code": exit_code,
            "tool_version": "0.2.0",
        }

    def _write_log(self, payload: Dict[str, Any]):
        """Write log to configured destination."""
        log_line = json.dumps(payload)

        # Write to file
        if self.log_file:
            try:
                with open(self.log_file, "a") as f:
                    f.write(log_line + "\n")
            except Exception as e:
                print(f"Warning: Failed to write audit log: {e}")

        # Send to Splunk HTTP Event Collector
        if self.splunk_url and self.splunk_token:
            try:
                import urllib.request
                headers = {
                    "Authorization": f"Splunk {self.splunk_token}",
                    "Content-Type": "application/json",
                }
                req = urllib.request.Request(
                    self.splunk_url,
                    data=json.dumps({"event": payload}).encode("utf-8"),
                    headers=headers,
                    method="POST"
                )
                urllib.request.urlopen(req, timeout=5)
            except Exception as e:
                print(f"Warning: Failed to send to Splunk: {e}")

        # Send to syslog server
        if self.syslog_server:
            try:
                import socket
                host, port = self.syslog_server.split(":")
                port = int(port)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))
                syslog_msg = f"<134>1 {datetime.utcnow().isoformat()} secops - - - - {log_line}"
                sock.sendall(syslog_msg.encode("utf-8"))
                sock.close()
            except Exception as e:
                print(f"Warning: Failed to send to syslog: {e}")


def setup_audit_logging(config_path: Optional[str] = None) -> AuditLogger:
    """Setup audit logging from config file."""
    import yaml
    config = {}
    paths = [config_path] if config_path else ["configs/audit.yaml", "audit.yaml"]

    for p in paths:
        if os.path.exists(p):
            with open(p, "r") as f:
                data = yaml.safe_load(f)
                config = data.get("audit", {})
                break

    return AuditLogger(config)
