"""
notify_telegram.py
Antigravity IDE -> Telegram Notification & Telemetry Tool

Enables the Antigravity agent (and any script) to send text messages,
desktop screenshots, and real-time system metrics directly to Telegram.
"""

from __future__ import annotations

import os
import sys

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Strip antivirus SSL keylogger proxy to prevent PermissionError
os.environ.pop("SSLKEYLOGFILE", None)

import argparse
import io
import json
import logging
import ssl
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

# Try to use truststore for Windows SSL cert store
try:
    import truststore
    truststore.inject_into_ssl()
except Exception:
    pass

from dotenv import load_dotenv

ENV_PATH = Path(__file__).parent.resolve() / ".env"
load_dotenv(ENV_PATH)

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
DEFAULT_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

# If not in .env, check whitelist.json for authorized chat ID
if not DEFAULT_CHAT_ID or DEFAULT_CHAT_ID == "None":
    try:
        wl_path = Path(__file__).parent.resolve() / "whitelist.json"
        if wl_path.exists():
            wl = json.loads(wl_path.read_text(encoding="utf-8"))
            ids = wl.get("allowed_user_ids", [])
            if ids:
                DEFAULT_CHAT_ID = str(ids[0])
    except Exception:
        pass


def get_credentials(chat_id: str | int | None = None) -> tuple[str, str]:
    token = BOT_TOKEN or os.getenv("TELEGRAM_BOT_TOKEN", "")
    target_chat = str(chat_id or DEFAULT_CHAT_ID)
    if not token:
        raise ValueError("TELEGRAM_BOT_TOKEN is not configured in .env")
    if not target_chat:
        raise ValueError("TELEGRAM_CHAT_ID is not configured in .env")
    return token, target_chat


def send_message(text: str, chat_id: str | int | None = None, parse_mode: str = "Markdown") -> bool:
    """Send text message to Telegram."""
    token, cid = get_credentials(chat_id)
    url = f"https://api.telegram.org/bot{token}/sendMessage"

    payload = {
        "chat_id": cid,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }

    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            return res.get("ok", False)
    except Exception as e:
        # Fallback to plain text if Markdown parsing fails
        if parse_mode != "":
            return send_message(text, chat_id=cid, parse_mode="")
        print(f"[notify_telegram] Error sending message: {e}", file=sys.stderr)
        return False


def attach_to_user_desktop():
    """Ensure the current thread is attached to the interactive 'Default' desktop on Windows."""
    if sys.platform == "win32":
        try:
            import ctypes
            u = ctypes.windll.user32
            DESKTOP_ALL = 0x1FF
            h_default = u.OpenDesktopW("Default", 0, False, DESKTOP_ALL)
            if h_default:
                u.SetThreadDesktop(h_default)
        except Exception as e:
            print(f"[notify_telegram] attach_to_user_desktop note: {e}", file=sys.stderr)


def send_screenshot(caption: str = "📸 Desktop Screenshot", chat_id: str | int | None = None) -> bool:
    """Take a full desktop screenshot and send it as a photo to Telegram."""
    token, cid = get_credentials(chat_id)
    attach_to_user_desktop()

    try:
        from PIL import ImageGrab
        img = ImageGrab.grab()
    except Exception as e:
        print(f"[notify_telegram] Failed to capture screen: {e}", file=sys.stderr)
        send_message(f"⚠️ Screenshot capture failed: {e}\n(Display may be asleep or locked)", chat_id=cid)
        return False

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85, optimize=True)
    photo_bytes = buf.getvalue()

    return _send_photo_bytes(photo_bytes, caption=caption, chat_id=cid, token=token)


def _send_photo_bytes(photo_bytes: bytes, caption: str, chat_id: str, token: str) -> bool:
    url = f"https://api.telegram.org/bot{token}/sendPhoto"
    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"

    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="chat_id"\r\n\r\n'
        f"{chat_id}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="caption"\r\n\r\n'
        f"{caption}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="photo"; filename="screenshot.jpg"\r\n'
        f"Content-Type: image/jpeg\r\n\r\n"
    ).encode("utf-8")

    footer = f"\r\n--{boundary}--\r\n".encode("utf-8")
    body = header + photo_bytes + footer

    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            return res.get("ok", False)
    except Exception as e:
        print(f"[notify_telegram] Error sending photo: {e}", file=sys.stderr)
        return False


def send_status(chat_id: str | int | None = None) -> bool:
    """Gather real-time system stats (CPU, RAM, GPU, active window) and send to Telegram."""
    lines = ["🖥️ **Workstation Real-Time Telemetry**", "━━━━━━━━━━━━━━━━━━━━"]

    # CPU & RAM
    try:
        import psutil
        cpu_pct = psutil.cpu_percent(interval=0.3)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("C:")
        lines.append(f"⚙️ **CPU**: `{cpu_pct}%`")
        lines.append(f"🧠 **RAM**: `{mem.used / (1024**3):.1f} GB` / `{mem.total / (1024**3):.1f} GB` ({mem.percent}%)")
        lines.append(f"💾 **Disk C:** `{disk.free / (1024**3):.1f} GB` free of `{disk.total / (1024**3):.1f} GB`")
    except Exception:
        pass

    # GPU
    try:
        res = os.popen(
            "nvidia-smi --query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits"
        ).read().strip()
        if res:
            parts = [p.strip() for p in res.split(",")]
            if len(parts) >= 5:
                lines.append(f"🎮 **GPU**: {parts[0]}")
                lines.append(f"   Temp: `{parts[1]}°C` | Load: `{parts[2]}%` | VRAM: `{parts[3]}MB / {parts[4]}MB`")
    except Exception:
        pass

    # Active Foreground Window Title
    try:
        import ctypes
        user32 = ctypes.windll.user32
        h_wnd = user32.GetForegroundWindow()
        length = user32.GetWindowTextLengthW(h_wnd)
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(h_wnd, buf, length + 1)
        win_title = buf.value or "None"
        lines.append(f"🪟 **Active Window**: `{win_title[:60]}`")
    except Exception:
        pass

    lines.append("━━━━━━━━━━━━━━━━━━━━")
    lines.append("⚡ Antigravity IDE Agent Active")

    return send_message("\n".join(lines), chat_id=chat_id)


def main():
    parser = argparse.ArgumentParser(description="Send notifications and screenshots to Telegram")
    parser.add_argument("--msg", type=str, help="Send text message")
    parser.add_argument("--screenshot", action="store_true", help="Capture and send desktop screenshot")
    parser.add_argument("--caption", type=str, default="📸 Desktop Screenshot", help="Caption for screenshot")
    parser.add_argument("--status", action="store_true", help="Send hardware and system telemetry")
    parser.add_argument("--chat-id", type=str, help="Override destination Telegram chat ID")

    args = parser.parse_args()

    if args.screenshot:
        success = send_screenshot(caption=args.caption, chat_id=args.chat_id)
        print(f"Screenshot sent: {success}")
        sys.exit(0 if success else 1)

    if args.status:
        success = send_status(chat_id=args.chat_id)
        print(f"Status sent: {success}")
        sys.exit(0 if success else 1)

    if args.msg:
        success = send_message(args.msg, chat_id=args.chat_id)
        print(f"Message sent: {success}")
        sys.exit(0 if success else 1)

    parser.print_help()


if __name__ == "__main__":
    main()
