import os
import sys
from pathlib import Path

# Unset SSLKEYLOGFILE for antivirus protection compatibility
os.environ.pop("SSLKEYLOGFILE", None)

print("--- [TEST 1] Testing Imports ---")
try:
    import psutil
    from PIL import ImageGrab
    from telegram import Update, ReplyKeyboardMarkup, InlineKeyboardMarkup
    from telegram.ext import Application
    print("✅ All libraries imported successfully.")
except Exception as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)

print("\n--- [TEST 2] Testing Configuration & Auth ---")
import bot
from bot import ALLOWED_USERNAME, BOT_TOKEN, is_authorized, get_state, save_state

# is_authorized() whitelists matching users and saves whitelist.json. The dummy IDs below
# are real Telegram account IDs, so never let the test persist them.
bot.save_whitelist = lambda: None
_real_whitelist = set(bot.whitelisted_ids)

class DummyUser:
    def __init__(self, id, username):
        self.id = id
        self.username = username

user_noah = DummyUser(12345678, "noahlimjj")
user_hacker = DummyUser(99999999, "unknown_stranger")

assert is_authorized(user_noah) == True, "Noah should be authorized"
assert is_authorized(user_hacker) == False, "Stranger should be rejected"
bot.whitelisted_ids.clear()
bot.whitelisted_ids.update(_real_whitelist)
print(f"✅ Auth check passed. @{ALLOWED_USERNAME} is authorized, strangers are blocked.")

print("\n--- [TEST 3] Testing Hardware & Status Reporting ---")
from bot import build_status_text
status_str = build_status_text(12345678)
print("Status Output Sample:")
print(status_str)
assert "System Status" in status_str, "Status should contain System Status"
print("✅ Hardware status generated cleanly.")

print("\n--- [TEST 4] Testing Screenshot Capture ---")
try:
    img = ImageGrab.grab(all_screens=True)
    print(f"✅ Desktop screenshot captured successfully. Dimensions: {img.size}")
except Exception as e:
    print(f"❌ Screenshot failed: {e}")

print("\n--- [TEST 5] Testing State Management & Folder Resolution ---")
state = get_state(12345678)
assert "cwd" in state, "State must have cwd"
assert Path(state["cwd"]).exists(), f"CWD {state['cwd']} must exist"
print(f"✅ State verified. Active CWD: {state['cwd']}, Model: {state['model']}")

print("\n--- [TEST 6] Testing Antigravity IDE Connection ---")
import asyncio
from bot import get_ls_env, ide_conversations
ls = asyncio.run(get_ls_env())
assert ls, "Antigravity IDE language server not found. Is the IDE open?"
convs = asyncio.run(ide_conversations())
print(f"✅ Connected to IDE at {ls['address']}, {len(convs)} conversation(s) found.")

print("\n--- [TEST 7] Testing Quota Fetching ---")
from bot import build_quota_text
quota_text = asyncio.run(build_quota_text())
print("Quota Output Sample:")
print(quota_text[:300] + "...")
assert "Quota Status" in quota_text, "Quota should come from the IDE"
print("✅ Quota fetched successfully.")

print("\n===============================")
print("🎉 ALL TESTS PASSED SUCCESSFULLY!")
print("===============================")
