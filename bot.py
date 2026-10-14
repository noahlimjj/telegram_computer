import os
import sys

# Ensure UTF-8 output on Windows consoles to prevent UnicodeEncodeError with emojis
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Strip AVG/antivirus SSL keylogger proxy to prevent PermissionError in Python ssl/urllib3
os.environ.pop("SSLKEYLOGFILE", None)
os.environ["PYTHONIOENCODING"] = "utf-8"

import truststore
truststore.inject_into_ssl()

# AVG intercepts HTTPS with its own root cert, which isn't always in the Windows store
# truststore reads. Trust it explicitly in every default SSL context (used by httpx).
import ssl
AVG_CERT = r"C:\ProgramData\AVG\Antivirus\wscert.pem"
if os.path.exists(AVG_CERT):
    _create_default_context = ssl.create_default_context
    def _create_context_with_avg(*args, **kwargs):
        ctx = _create_default_context(*args, **kwargs)
        try:
            ctx.load_verify_locations(AVG_CERT)
        except Exception:
            pass
        return ctx
    ssl.create_default_context = _create_context_with_avg

import html
import json
import time
import uuid
import shutil
import asyncio
import logging
from io import BytesIO
from pathlib import Path
from datetime import datetime

import httpx
import psutil
from PIL import ImageGrab
from dotenv import load_dotenv
import telegram.error
from telegram import (
    Update,
    ReplyKeyboardMarkup,
    KeyboardButton,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
)
from telegram.constants import ParseMode, ChatAction
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
)

# Configuration & Paths
BASE_DIR = Path(__file__).parent.resolve()
ENV_PATH = BASE_DIR / ".env"
STATE_FILE = BASE_DIR / "user_state.json"
WHITELIST_FILE = BASE_DIR / "whitelist.json"

load_dotenv(ENV_PATH)

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ALLOWED_USERNAME = os.getenv("ALLOWED_USERNAME", "noahlimjj").lower().lstrip("@")
CONVERSATION_ID = os.getenv("CONVERSATION_ID", "latest")

if not BOT_TOKEN:
    raise ValueError("TELEGRAM_BOT_TOKEN is not configured in .env")

# Logging setup
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("AntigravityTelegramBot")
# httpx logs every request URL at INFO, and Telegram URLs contain the bot token
logging.getLogger("httpx").setLevel(logging.WARNING)

# The IDE conversation the user last typed into, refreshed from the IDE by transcript_monitor
_latest_user_conv: str | None = None

def get_active_conversation_id(chat_id: int | None = None) -> str:
    """Resolve active Antigravity IDE conversation ID.

    Order: the chat's pick from /conv ("auto" = always follow the latest), then
    CONVERSATION_ID in .env, then the IDE chat the user last typed into.
    """
    follow_latest = False
    if chat_id:
        picked = get_state(chat_id).get("conversation_id")
        if picked == "auto":
            follow_latest = True
        elif picked:
            return picked
    env_conv = os.getenv("CONVERSATION_ID")
    if not follow_latest and env_conv and env_conv not in ("latest", "auto"):
        return env_conv
    if _latest_user_conv:
        return _latest_user_conv
    # IDE not queried yet: fall back to the conversation with the most recent file activity.
    # Directory mtimes don't change when files inside are written, so look at the files.
    try:
        ide_dir = Path.home() / ".gemini" / "antigravity-ide"
        activity: dict[str, float] = {}
        conv_dir = ide_dir / "conversations"
        if conv_dir.exists():
            for f in conv_dir.glob("*.db*"):
                cid = f.name.split(".")[0]
                activity[cid] = max(activity.get(cid, 0), f.stat().st_mtime)
        brain_dir = ide_dir / "brain"
        if brain_dir.exists():
            for t in brain_dir.glob("*/.system_generated/logs/transcript.jsonl"):
                cid = t.parents[2].name
                activity[cid] = max(activity.get(cid, 0), t.stat().st_mtime)
        if activity:
            return max(activity, key=activity.get)
    except Exception as e:
        logger.warning(f"Failed to auto-detect latest conversation: {e}")
    return "latest"

# Antigravity IDE connection
# The bot talks to the IDE's own language server, the same one the IDE chat panel uses,
# so everything runs on the IDE's existing sign-in (no separate CLI login). Its port and
# CSRF token change on every IDE restart, so they're discovered from the running process.
LS_EXE_NAME = "language_server_windows_x64.exe"
LS_SERVICE = "exa.language_server_pb.LanguageServerService"
_ls_env_cache: dict | None = None

class IDEUnavailable(Exception):
    pass

def _ls_env_candidates() -> list[dict]:
    """Possible language server connections, best guess first."""
    cands = []
    addr, csrf = os.environ.get("ANTIGRAVITY_LS_ADDRESS"), os.environ.get("ANTIGRAVITY_CSRF_TOKEN")
    if addr and csrf:
        cands.append({"address": addr, "csrf": csrf})
    servers = []
    for p in psutil.process_iter(["name", "cmdline"]):
        try:
            if (p.info["name"] or "").lower() != LS_EXE_NAME:
                continue
            args = p.info["cmdline"] or []
            token = args[args.index("--csrf_token") + 1]
            ports = sorted(c.laddr.port for c in p.net_connections(kind="tcp") if c.status == psutil.CONN_LISTEN)
            servers.append(("--workspace_id" in args, token, ports))
        except (psutil.Error, ValueError, IndexError):
            continue
    servers.sort(key=lambda s: s[0])  # IDE-wide server (no workspace) first
    for _, token, ports in servers:
        for port in ports:
            cands.append({"address": f"127.0.0.1:{port}", "csrf": token})
    return cands

async def _post_ls(ls: dict, method: str, body: dict, timeout: float) -> dict:
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(
            f"http://{ls['address']}/{LS_SERVICE}/{method}",
            json=body,
            headers={"X-Codeium-Csrf-Token": ls["csrf"], "Connect-Protocol-Version": "1"},
        )
    if r.status_code != 200:
        raise IDEUnavailable(f"{method} failed: HTTP {r.status_code} {r.text[:200]}")
    return r.json()

async def get_ls_env(refresh: bool = False) -> dict | None:
    """Find (and cache) a reachable language server."""
    global _ls_env_cache
    if _ls_env_cache and not refresh:
        return _ls_env_cache
    _ls_env_cache = None
    for cand in _ls_env_candidates():
        try:
            await _post_ls(cand, "GetUserStatus", {}, timeout=3)
        except Exception:
            continue
        _ls_env_cache = cand
        logger.info(f"Connected to Antigravity language server at {cand['address']}")
        return cand
    return None

async def ide_rpc(method: str, body: dict | None = None, timeout: float = 30) -> dict:
    """Call the IDE language server, rediscovering it once if the IDE restarted."""
    last_err: Exception | None = None
    for refresh in (False, True):
        ls = await get_ls_env(refresh=refresh)
        if not ls:
            break
        try:
            return await _post_ls(ls, method, body or {}, timeout)
        except Exception as e:
            last_err = e
    raise IDEUnavailable(f"Couldn't reach Antigravity IDE ({last_err or 'IDE not running'}). Is the IDE open?")

async def ide_user_status() -> dict:
    """Account, plan and per-model quota."""
    return (await ide_rpc("GetUserStatus")).get("userStatus", {})

async def ide_models() -> list[dict]:
    """Models offered in the IDE's model picker (label, modelId, modelOrAlias, quotaInfo)."""
    status = await ide_user_status()
    return status.get("cascadeModelConfigData", {}).get("clientModelConfigs", [])

async def ide_conversations() -> list[tuple[str, dict]]:
    """IDE conversations, most recently used first."""
    convs = (await ide_rpc("GetAllCascadeTrajectories")).get("trajectorySummaries", {})
    return sorted(convs.items(), key=lambda kv: kv[1].get("lastModifiedTime", ""), reverse=True)

async def refresh_latest_user_conversation():
    """Remember which IDE chat the user last typed into (used when following the latest)."""
    global _latest_user_conv
    convs = await ide_conversations()
    typed = [(info.get("lastUserInputTime", ""), cid) for cid, info in convs if info.get("lastUserInputTime")]
    if typed:
        _latest_user_conv = max(typed)[1]

async def ide_send_message(conv_id: str, text: str, model_id: str | None = None):
    """Post text into an IDE conversation as a user message, like typing in the chat panel."""
    data = (await ide_user_status()).get("cascadeModelConfigData", {})
    model = next((c["modelOrAlias"] for c in data.get("clientModelConfigs", [])
                  if c.get("modelId") == model_id and c.get("modelOrAlias")), None)
    model = model or data.get("defaultOverrideModelConfig", {}).get("modelOrAlias")
    planner: dict = {"conversational": {}}
    if model:
        planner["requestedModel"] = model
    await ide_rpc("SendUserCascadeMessage", {
        "cascadeId": conv_id,
        "items": [{"text": text}],
        "cascadeConfig": {"plannerConfig": planner},
    })

async def ide_new_conversation() -> str:
    """Start a new, empty IDE conversation and return its ID."""
    res = await ide_rpc("StartCascade", {
        "source": "CORTEX_TRAJECTORY_SOURCE_CASCADE_CLIENT",
        "trajectoryType": "CORTEX_TRAJECTORY_TYPE_CASCADE",
    })
    return res["cascadeId"]

async def ide_stop(conv_id: str):
    """Stop the agent's current run in a conversation (the IDE's stop button)."""
    await ide_rpc("CancelCascadeInvocation", {"cascadeId": conv_id})

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
            logger.warning(f"attach_to_user_desktop note: {e}")

# Whitelist storage
whitelisted_ids = set()
if WHITELIST_FILE.exists():
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            whitelisted_ids = set(data.get("allowed_user_ids", []))
    except Exception as e:
        logger.warning(f"Could not read whitelist: {e}")

def save_whitelist():
    try:
        with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
            json.dump({"allowed_user_ids": list(whitelisted_ids)}, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save whitelist: {e}")

def is_authorized(user) -> bool:
    if not user:
        return False
    username = (user.username or "").lower().lstrip("@")
    user_id = user.id

    if username == ALLOWED_USERNAME:
        if user_id not in whitelisted_ids:
            whitelisted_ids.add(user_id)
            save_whitelist()
            logger.info(f"Authorized user @{username} with User ID {user_id}")
        return True

    return user_id in whitelisted_ids

async def check_auth(update: Update) -> bool:
    user = update.effective_user
    if not is_authorized(user):
        user_info = f"ID: {user.id if user else 'Unknown'}, Username: @{user.username if user else 'None'}"
        logger.warning(f"Unauthorized access attempt from {user_info}")
        if update.effective_message:
            await update.effective_message.reply_text("⛔ Unauthorized. This workstation bot is locked to @noahlimjj.")
        return False
    return True

# Persistent Session State
DEFAULT_STATE = {
    "cwd": str(Path.home()),
    "conversation_id": None,
    "model": "gemini-3.8-flash-high",
    "mode": "auto",
    "effort": "high",
    "history_count": 0
}

session_state = {}
if STATE_FILE.exists():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            session_state = json.load(f)
    except Exception as e:
        logger.warning(f"Could not load state: {e}")

def get_state(chat_id: int) -> dict:
    key = str(chat_id)
    if key not in session_state:
        session_state[key] = dict(DEFAULT_STATE)
        save_state()
    return session_state[key]

def save_state():
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(session_state, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save state: {e}")

# Active background subprocesses
active_subprocesses = {}

# Available Models
AVAILABLE_MODELS = [
    ("gemini-3.8-flash-high", "Gemini 3.8 Flash (High) - Fast & Smart"),
    ("gemini-3.8-flash-medium", "Gemini 3.8 Flash (Medium)"),
    ("gemini-3.8-flash-low", "Gemini 3.8 Flash (Low)"),
    ("claude-sonnet-4-6", "Claude Sonnet 4.6 (Thinking)"),
    ("claude-opus-4-6-thinking", "Claude Opus 4.6 (Thinking) - Deep Logic"),
    ("gpt-oss-120b-medium", "GPT-OSS 120B (Medium)"),
]

# Quick Project Bookmarks
QUICK_PROJECTS = {
    "investment": (r"C:\Users\noahl\projects\investment", "📈 Investment Repo"),
    "home": (str(Path.home()), "🏠 Home"),
    "ddrive": ("D:\\", "💾 D: Drive"),
    "desktop": (str(Path.home() / "Desktop"), "💻 Desktop"),
    "downloads": (str(Path.home() / "Downloads"), "📥 Downloads"),
    "scratch": (r"C:\Users\noahl\.gemini\antigravity\scratch", "🧪 Scratch"),
    "bot": (r"C:\Users\noahl\.gemini\antigravity\scratch\telegram-agent-bot", "🤖 Bot Project"),
}

# Keyboards
def get_main_keyboard():
    """Always-visible bottom buttons on Telegram."""
    keyboard = [
        [KeyboardButton("📊 Quota & Tokens"), KeyboardButton("🖥️ System Status")],
        [KeyboardButton("📂 Files & Projects"), KeyboardButton("🐙 Git & GitHub")],
        [KeyboardButton("📸 Screenshot"), KeyboardButton("🧠 Switch Model")],
        [KeyboardButton("🗂️ IDE Chats"), KeyboardButton("🛑 Stop Agent")],
        [KeyboardButton("🔄 Reset Agent"), KeyboardButton("❓ Help & Commands")]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)

async def get_model_inline_keyboard(current_model: str):
    """Model picker built from the IDE's own model list, with each model's remaining quota."""
    try:
        models = [(m["modelId"], m.get("label", m["modelId"]), m.get("quotaInfo"))
                  for m in await ide_models() if m.get("modelId")]
    except IDEUnavailable:
        models = [(m_id, desc, None) for m_id, desc in AVAILABLE_MODELS]
    buttons = []
    for m_id, label, quota in models:
        prefix = "✅ " if m_id == current_model else ""
        # Protobuf JSON omits zero values: quotaInfo without remainingFraction means none left
        suffix = f" · {int(round(float(quota.get('remainingFraction', 0)) * 100))}% left" if quota is not None else ""
        buttons.append([InlineKeyboardButton(f"{prefix}{label}{suffix}", callback_data=f"model:{m_id}")])
    return InlineKeyboardMarkup(buttons)

async def get_conversations_inline_keyboard(current_conv: str):
    """Picker for which IDE conversation Telegram messages go to."""
    status_icons = {"CASCADE_RUN_STATUS_RUNNING": "⏳", "CASCADE_RUN_STATUS_IDLE": "💤"}
    buttons = []
    for conv_id, info in (await ide_conversations())[:10]:
        prefix = "✅ " if conv_id == current_conv else status_icons.get(info.get("status"), "💬") + " "
        title = (info.get("summary") or "Untitled conversation")[:45]
        buttons.append([InlineKeyboardButton(f"{prefix}{title}", callback_data=f"conv:{conv_id}")])
    buttons.append([InlineKeyboardButton("🔄 Follow latest automatically", callback_data="conv:auto"),
                    InlineKeyboardButton("➕ New chat", callback_data="action:reset")])
    return InlineKeyboardMarkup(buttons)

def get_projects_inline_keyboard():
    buttons = []
    row = []
    for key, (path, label) in QUICK_PROJECTS.items():
        row.append(InlineKeyboardButton(label, callback_data=f"proj:{key}"))
        if len(row) == 2:
            buttons.append(row)
            row = []
    if row:
        buttons.append(row)
    buttons.append([InlineKeyboardButton("📂 Browse Current Folder", callback_data="browse:cwd")])
    return InlineKeyboardMarkup(buttons)

def get_git_inline_keyboard(is_repo: bool):
    if is_repo:
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("📊 Git Status", callback_data="git:status"),
             InlineKeyboardButton("🔍 Git Diff", callback_data="git:diff")],
            [InlineKeyboardButton("🔄 Git Pull", callback_data="git:pull"),
             InlineKeyboardButton("🚀 Git Push", callback_data="git:push")],
            [InlineKeyboardButton("📝 Quick Commit & Push", callback_data="git:quick_commit")]
        ])
    else:
        return InlineKeyboardMarkup([
            [InlineKeyboardButton("📦 Clone a Repo", callback_data="git:prompt_clone"),
             InlineKeyboardButton("📂 Browse Projects", callback_data="action:projects")]
        ])

def make_bar(fraction: float, length: int = 10) -> str:
    filled = int(round(fraction * length))
    filled = max(0, min(length, filled))
    return "█" * filled + "░" * (length - filled)

async def send_long_message(message, text: str, parse_mode=None, reply_markup=None):
    if not text:
        text = "(No output)"
    if len(text) > 8000:
        file_obj = BytesIO(text.encode("utf-8"))
        file_obj.name = "output.txt"
        await message.reply_document(
            document=file_obj,
            caption="📄 Output was too large for Telegram, sent as text file.",
            reply_markup=reply_markup
        )
        return

    MAX_LEN = 3900
    for i in range(0, len(text), MAX_LEN):
        chunk = text[i:i + MAX_LEN]
        is_last = (i + MAX_LEN) >= len(text)
        markup = reply_markup if is_last else None
        try:
            await message.reply_text(chunk, parse_mode=parse_mode, reply_markup=markup)
        except Exception:
            await message.reply_text(chunk, reply_markup=markup)

def is_git_repo(path_str: str) -> bool:
    try:
        p = Path(path_str)
        return (p / ".git").exists() or any((parent / ".git").exists() for parent in [p, *p.parents])
    except Exception:
        return False

def get_git_branch(path_str: str) -> str:
    try:
        res = os.popen(f'git -C "{path_str}" rev-parse --abbrev-ref HEAD').read().strip()
        return res if res else "unknown"
    except Exception:
        return "unknown"

def build_status_text(chat_id: int) -> str:
    cpu_pct = psutil.cpu_percent(interval=0.2)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("C:")

    gpu_info = "N/A"
    try:
        res = os.popen("nvidia-smi --query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits").read().strip()
        if res:
            parts = [p.strip() for p in res.split(",")]
            if len(parts) >= 5:
                gpu_info = f"{parts[0]}\n   Temp: `{parts[1]}°C` | Load: `{parts[2]}%` | VRAM: `{parts[3]}MB / {parts[4]}MB`"
    except Exception:
        pass

    state = get_state(chat_id)
    cwd = state["cwd"]
    git_status = f"Git: `{get_git_branch(cwd)}`" if is_git_repo(cwd) else "Git: None"

    return (
        f"🖥️ **System Status (Dell G5 Tower)**\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"⚙️ **CPU Load**: `{cpu_pct}%` (i9-10900KF)\n"
        f"🧠 **RAM**: `{mem.used / (1024**3):.1f} GB` / `{mem.total / (1024**3):.1f} GB` ({mem.percent}%)\n"
        f"💾 **Disk (C:)**: `{disk.free / (1024**3):.1f} GB` free of `{disk.total / (1024**3):.1f} GB`\n"
        f"🎮 **GPU**: {gpu_info}\n"
        f"📁 **Active Folder**: `{cwd}`\n"
        f"🌿 **Repo**: {git_status}\n"
        f"🧠 **Model**: `{state['model']}`\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ Status: Always-On Workstation Ready"
    )

async def build_quota_text() -> str:
    try:
        status = await ide_user_status()
    except IDEUnavailable as e:
        return f"❌ {html.escape(str(e))}"

    lines = ["📊 <b>Antigravity Token & Quota Status</b>\n━━━━━━━━━━━━━━━━━━━━"]
    plan = status.get("planStatus", {}).get("planInfo", {}).get("planName")
    if plan:
        lines.append(f"👤 Plan: <code>{html.escape(plan)}</code>")
    for cfg in status.get("cascadeModelConfigData", {}).get("clientModelConfigs", []):
        quota = cfg.get("quotaInfo")
        if quota is None:
            continue
        # Protobuf JSON omits zero values: no remainingFraction means the quota is used up
        frac = float(quota.get("remainingFraction", 0.0))
        reset_time = quota.get("resetTime", "")
        reset_str = ""
        if reset_time:
            try:
                reset_local = datetime.fromisoformat(reset_time.replace("Z", "+00:00")).astimezone()
                reset_str = f" (resets {reset_local.strftime('%a %d %b %H:%M')})"
            except ValueError:
                reset_str = f" (resets {reset_time})"
        lbl = html.escape(cfg.get('label', 'Model'))
        lines.append(f"• {lbl}:\n  <code>[{make_bar(frac, length=10)}] {int(round(frac * 100))}%</code>{html.escape(reset_str)}")

    lines.append("\n━━━━━━━━━━━━━━━━━━━━\n⚡ <i>Connected to active Antigravity IDE session.</i>")
    return "\n".join(lines)

# ==========================================
# COMMAND & BUTTON HANDLERS
# ==========================================

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    state = get_state(update.effective_chat.id)
    cwd = state["cwd"]
    git_info = f" (🌿 `{get_git_branch(cwd)}`)" if is_git_repo(cwd) else ""

    msg = (
        "🤖 **Antigravity Autonomous Mobile Workstation**\n\n"
        "Welcome Noah! Your PC is ready for full autonomous engineering from Telegram.\n\n"
        f"📁 **Active Project**: `{cwd}`{git_info}\n"
        f"🧠 **Model**: `{state['model']}`\n\n"
        "**What you can do:**\n"
        "• **Autonomous Coding**: Send any message to tell Antigravity to write, fix, debug, or build in the active repo.\n"
        "• **GitHub Workflow**:\n"
        "  - `/clone <url>`: Clone any repo and immediately make it your active workspace\n"
        "  - `/diff`: See code changes made by the AI agent\n"
        "  - `/commit <msg>` & `/push`: Push code back to GitHub\n"
        "• **Folder & Navigation**: `/cd <path>`, `/ls`, `/pwd`, `/projects`\n"
        "• **File Transfer**: Send files/photos to save to PC, or `/get <file>` to download\n"
        "• **Hardware & Terminal**: `/sys`, `/screen`, `/run <powershell>`\n"
        "• **Tap any quick button below** to control everything with one tap!"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, reply_markup=get_main_keyboard())

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    await start_command(update, context)

# Git & GitHub Operations
async def git_command_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    state = get_state(update.effective_chat.id)
    cwd = state["cwd"]
    is_repo = is_git_repo(cwd)

    if is_repo:
        branch = get_git_branch(cwd)
        status_raw = os.popen(f'git -C "{cwd}" status -s').read().strip()
        changes_summary = f"\nUncommitted changes:\n```\n{status_raw}\n```" if status_raw else "\n✨ Working tree clean."
        msg = f"🐙 **Git Manager**\nRepository: `{cwd}`\nBranch: `{branch}`{changes_summary}"
    else:
        msg = (
            f"🐙 **Git Manager**\nCurrent folder `{cwd}` is not a git repository.\n\n"
            "To clone a project, send:\n`/clone <github_repo_url>`"
        )
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, reply_markup=get_git_inline_keyboard(is_repo))

async def clone_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    if not context.args:
        await update.message.reply_text("Usage: `/clone <github_repo_url> [custom_folder_name]`", parse_mode=ParseMode.MARKDOWN)
        return

    url = context.args[0].strip()
    custom_name = context.args[1].strip() if len(context.args) > 1 else ""

    chat_id = update.effective_chat.id
    state = get_state(chat_id)
    cwd = state["cwd"]

    status_msg = await update.message.reply_text(f"⏳ **Cloning repository:**\n`{url}`\ninto `{cwd}`...", parse_mode=ParseMode.MARKDOWN)

    # Determine clone target name
    repo_name = custom_name or url.rstrip("/").split("/")[-1].replace(".git", "")
    target_dir = Path(cwd) / repo_name

    cmd = f"git clone {url}" + (f" \"{custom_name}\"" if custom_name else "")

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )
        stdout, stderr = await proc.communicate()
        out = stdout.decode("utf-8", errors="replace").strip()
        err = stderr.decode("utf-8", errors="replace").strip()

        if proc.returncode == 0:
            # Auto switch active folder to the cloned repo
            if target_dir.exists():
                state["cwd"] = str(target_dir)
                state["conversation_id"] = None
                state["history_count"] = 0
                save_state()

            branch = get_git_branch(str(target_dir))
            success_msg = (
                f"✅ **Repository Cloned Successfully!**\n\n"
                f"📁 **Active Folder switched to:**\n`{target_dir}`\n"
                f"🌿 **Branch:** `{branch}`\n\n"
                f"🚀 **Antigravity is ready.** Send your instructions to fix, code, or inspect this repo!"
            )
            inline_kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("📊 Git Status", callback_data="git:status"),
                 InlineKeyboardButton("📂 Browse Files", callback_data="browse:cwd")],
                [InlineKeyboardButton("🧠 Model Settings", callback_data="action:models")]
            ])
            await status_msg.edit_text(success_msg, parse_mode=ParseMode.MARKDOWN, reply_markup=inline_kb)
        else:
            await status_msg.edit_text(f"❌ **Git Clone Failed (Exit code {proc.returncode}):**\n```\n{err or out}\n```", parse_mode=ParseMode.MARKDOWN)

    except Exception as e:
        await status_msg.edit_text(f"❌ Error during git clone: {e}")

async def diff_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    state = get_state(update.effective_chat.id)
    cwd = state["cwd"]

    if not is_git_repo(cwd):
        await update.message.reply_text(f"❌ `{cwd}` is not a git repository.", parse_mode=ParseMode.MARKDOWN)
        return

    status_raw = os.popen(f'git -C "{cwd}" status -s').read().strip()
    diff_raw = os.popen(f'git -C "{cwd}" diff').read().strip()

    if not diff_raw and not status_raw:
        await update.message.reply_text("✨ No changes found. Working directory is clean.", parse_mode=ParseMode.MARKDOWN)
        return

    msg = f"🔍 **Git Changes in `{cwd}`:**\n\n"
    if status_raw:
        msg += f"**Files Modified:**\n```\n{status_raw}\n```\n"
    if diff_raw:
        msg += f"**Diff:**\n```diff\n{diff_raw}\n```"

    inline_kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🚀 Git Push", callback_data="git:push"),
         InlineKeyboardButton("📝 Quick Commit", callback_data="git:quick_commit")]
    ])
    await send_long_message(update.message, msg, parse_mode=ParseMode.MARKDOWN, reply_markup=inline_kb)

async def commit_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    commit_msg = " ".join(context.args).strip() if context.args else f"Update via Antigravity Mobile ({datetime.now().strftime('%Y-%m-%d %H:%M')})"
    state = get_state(update.effective_chat.id)
    cwd = state["cwd"]

    if not is_git_repo(cwd):
        await update.message.reply_text(f"❌ `{cwd}` is not a git repository.", parse_mode=ParseMode.MARKDOWN)
        return

    add_res = os.popen(f'git -C "{cwd}" add -A').read().strip()
    commit_res = os.popen(f'git -C "{cwd}" commit -m "{commit_msg}"').read().strip()

    inline_kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🚀 Push to GitHub Now", callback_data="git:push")]
    ])
    await update.message.reply_text(f"📝 **Committed Changes:**\n```\n{commit_res}\n```", parse_mode=ParseMode.MARKDOWN, reply_markup=inline_kb)

async def push_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    state = get_state(update.effective_chat.id)
    cwd = state["cwd"]

    if not is_git_repo(cwd):
        await update.message.reply_text(f"❌ `{cwd}` is not a git repository.", parse_mode=ParseMode.MARKDOWN)
        return

    status_msg = await update.message.reply_text("🚀 Pushing to remote repository...")
    try:
        proc = await asyncio.create_subprocess_shell(
            "git push",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )
        stdout, stderr = await proc.communicate()
        out = stdout.decode("utf-8", errors="replace").strip()
        err = stderr.decode("utf-8", errors="replace").strip()

        if proc.returncode == 0:
            await status_msg.edit_text(f"✅ **Push Successful!**\n```\n{out or err or 'Everything up-to-date.'}\n```", parse_mode=ParseMode.MARKDOWN)
        else:
            await status_msg.edit_text(f"❌ **Push Failed:**\n```\n{err or out}\n```", parse_mode=ParseMode.MARKDOWN)
    except Exception as e:
        await status_msg.edit_text(f"❌ Push error: {e}")

async def pull_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    state = get_state(update.effective_chat.id)
    cwd = state["cwd"]

    if not is_git_repo(cwd):
        await update.message.reply_text(f"❌ `{cwd}` is not a git repository.", parse_mode=ParseMode.MARKDOWN)
        return

    res = os.popen(f'git -C "{cwd}" pull').read().strip()
    await update.message.reply_text(f"🔄 **Git Pull:**\n```\n{res}\n```", parse_mode=ParseMode.MARKDOWN)

async def raw_git_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    args = " ".join(context.args).strip() if context.args else "status"
    state = get_state(update.effective_chat.id)
    cwd = state["cwd"]

    proc = await asyncio.create_subprocess_shell(
        f"git {args}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd
    )
    stdout, stderr = await proc.communicate()
    out = stdout.decode("utf-8", errors="replace").strip()
    err = stderr.decode("utf-8", errors="replace").strip()

    result = f"🐙 `git {args}` in `{cwd}`:\n"
    if out:
        result += f"```\n{out}\n```\n"
    if err:
        result += f"```\n{err}\n```\n"
    if not out and not err:
        result += "✅ Done (No output)."

    await send_long_message(update.message, result, parse_mode=ParseMode.MARKDOWN)

# System & Screen Handlers
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    text = build_status_text(update.effective_chat.id)
    inline_kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄 Refresh Stats", callback_data="refresh:status"),
         InlineKeyboardButton("📸 Take Screenshot", callback_data="action:screenshot")],
        [InlineKeyboardButton("📊 View Token Quota", callback_data="action:quota")]
    ])
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN, reply_markup=inline_kb)

async def screen_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    status_msg = await update.message.reply_text("📸 Capturing desktop screenshot...")
    try:
        attach_to_user_desktop()
        img = ImageGrab.grab()
        bio = BytesIO()
        bio.name = "screenshot.jpg"
        img.save(bio, "JPEG", quality=85, optimize=True)
        bio.seek(0)
        inline_kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔄 Retake", callback_data="action:screenshot"),
             InlineKeyboardButton("🖥️ Stats", callback_data="refresh:status")]
        ])
        await update.message.reply_photo(photo=bio, caption="🖥️ Current Desktop Screen", reply_markup=inline_kb)
        await status_msg.delete()
    except Exception as e:
        await status_msg.edit_text(f"⚠️ Screenshot note: {e}\n(Windows display may be asleep/locked; terminal commands still work 100%).")

async def usage_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    status_msg = await update.message.reply_text("📊 Checking token quota and rate limits...")
    text = await build_quota_text()
    inline_kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄 Refresh Quota", callback_data="action:quota"),
         InlineKeyboardButton("🧠 Change Model", callback_data="action:models")]
    ])
    try:
        await status_msg.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=inline_kb)
    except Exception:
        try:
            await status_msg.edit_text(text, parse_mode=ParseMode.MARKDOWN, reply_markup=inline_kb)
        except Exception:
            await status_msg.edit_text(text, reply_markup=inline_kb)

# Projects & Folder Navigation
async def projects_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    state = get_state(update.effective_chat.id)
    msg = (
        f"📑 **Project & Folder Manager**\n"
        f"Current Folder: `{state['cwd']}`\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"Tap any button below to instantly switch the agent's working folder:"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, reply_markup=get_projects_inline_keyboard())

async def pwd_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    state = get_state(update.effective_chat.id)
    cwd = Path(state["cwd"])
    free_gb = shutil.disk_usage(cwd).free / (1024**3) if cwd.exists() else 0
    git_info = f"🌿 Git Branch: `{get_git_branch(str(cwd))}`\n" if is_git_repo(str(cwd)) else ""
    msg = (
        f"📁 **Active Working Directory**\n"
        f"`{cwd}`\n"
        f"{git_info}"
        f"Free Space: `{free_gb:.1f} GB`"
    )
    inline_kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("📂 Browse Files", callback_data="browse:cwd"),
         InlineKeyboardButton("📑 Change Folder", callback_data="action:projects")]
    ])
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, reply_markup=inline_kb)

async def cd_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    chat_id = update.effective_chat.id
    state = get_state(chat_id)

    if not context.args:
        await update.message.reply_text(
            f"📁 Current folder: `{state['cwd']}`\nUse the buttons below or type `/cd <path>`:",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=get_projects_inline_keyboard()
        )
        return

    arg = " ".join(context.args).strip()
    if arg in QUICK_PROJECTS:
        target_path = Path(QUICK_PROJECTS[arg][0])
    elif arg.startswith("~"):
        target_path = Path.home() / arg[1:].lstrip("\\/")
    else:
        target_path = Path(arg)
        if not target_path.is_absolute():
            target_path = Path(state["cwd"]) / target_path

    try:
        resolved = target_path.resolve()
        if not resolved.exists() or not resolved.is_dir():
            await update.message.reply_text(f"❌ Directory not found:\n`{resolved}`", parse_mode=ParseMode.MARKDOWN)
            return

        state["cwd"] = str(resolved)
        save_state()
        inline_kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("📂 Browse Files", callback_data="browse:cwd"),
             InlineKeyboardButton("📑 Switch Folder", callback_data="action:projects")]
        ])
        await update.message.reply_text(f"📂 Switched working directory to:\n`{resolved}`", parse_mode=ParseMode.MARKDOWN, reply_markup=inline_kb)
    except Exception as e:
        await update.message.reply_text(f"❌ Error switching directory: {e}")

async def ls_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    state = get_state(update.effective_chat.id)
    target = Path(state["cwd"])
    if context.args:
        arg_path = Path(" ".join(context.args))
        target = arg_path if arg_path.is_absolute() else target / arg_path

    try:
        resolved = target.resolve()
        if not resolved.exists():
            await update.message.reply_text(f"❌ Path does not exist: `{resolved}`", parse_mode=ParseMode.MARKDOWN)
            return

        items = list(resolved.iterdir())
        dirs = sorted([d for d in items if d.is_dir()], key=lambda x: x.name.lower())
        files = sorted([f for f in items if f.is_file()], key=lambda x: x.name.lower())

        lines = [f"📂 **Listing:** `{resolved}`\n━━━━━━━━━━━━━━━━━━━━"]
        for d in dirs[:25]:
            lines.append(f"📁 `{d.name}/`")
        for f in files[:35]:
            sz = f.stat().st_size
            sz_str = f"{sz / (1024*1024):.1f} MB" if sz > 1024*1024 else (f"{sz / 1024:.1f} KB" if sz > 1024 else f"{sz} B")
            lines.append(f"📄 `{f.name}` ({sz_str})")

        total = len(dirs) + len(files)
        displayed = min(25, len(dirs)) + min(35, len(files))
        if total > displayed:
            lines.append(f"\n_...and {total - displayed} more items._")

        lines.append(f"\nTotal: `{len(dirs)} folders`, `{len(files)} files`")
        inline_kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("📑 Switch Project", callback_data="action:projects"),
             InlineKeyboardButton("⬆️ Up Folder", callback_data="browse:up")]
        ])
        await send_long_message(update.message, "\n".join(lines), parse_mode=ParseMode.MARKDOWN, reply_markup=inline_kb)

    except Exception as e:
        await update.message.reply_text(f"❌ Error listing directory: {e}")

# Models & Settings
async def model_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    chat_id = update.effective_chat.id
    state = get_state(chat_id)

    if context.args:
        choice = context.args[0].strip()
        try:
            valid_ids = [m.get("modelId") for m in await ide_models()]
        except IDEUnavailable:
            valid_ids = [m[0] for m in AVAILABLE_MODELS]
        if choice in valid_ids:
            state["model"] = choice
            save_state()
            await update.message.reply_text(f"✅ Model switched to: `{choice}`", parse_mode=ParseMode.MARKDOWN)
            return

    msg = (f"🧠 **AI Model Selection** (from Antigravity IDE)\nCurrently active: `{state['model']}`\n"
           f"Used for your next Telegram messages. Tap to switch:")
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, reply_markup=await get_model_inline_keyboard(state["model"]))

async def new_conv_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    await update.message.reply_text(await start_new_ide_chat(update.effective_chat.id), parse_mode=ParseMode.HTML)

async def start_new_ide_chat(chat_id: int) -> str:
    """Open a fresh IDE conversation and point this Telegram chat at it. Returns the reply text."""
    try:
        conv_id = await ide_new_conversation()
    except IDEUnavailable as e:
        return f"❌ {html.escape(str(e))}"
    state = get_state(chat_id)
    state["conversation_id"] = conv_id
    state["history_count"] = 0
    save_state()
    return (f"🆕 <b>New Antigravity IDE chat started</b>\n"
            f"Session: <code>{conv_id[:8]}...</code>\n"
            f"Your next message starts it. Use /conv to switch back to another chat.")

# File Upload / Download
async def get_file_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    if not context.args:
        await update.message.reply_text("Usage: `/get <filename_or_path>`", parse_mode=ParseMode.MARKDOWN)
        return
    filename = " ".join(context.args).strip()
    state = get_state(update.effective_chat.id)
    file_path = Path(filename) if Path(filename).is_absolute() else Path(state["cwd"]) / filename

    if not file_path.exists() or not file_path.is_file():
        await update.message.reply_text(f"❌ File not found:\n`{file_path}`", parse_mode=ParseMode.MARKDOWN)
        return

    size_mb = file_path.stat().st_size / (1024 * 1024)
    if size_mb > 49:
        await update.message.reply_text(f"❌ File is too large for Telegram ({size_mb:.1f} MB, limit is 50 MB).")
        return

    status_msg = await update.message.reply_text(f"📤 Uploading `{file_path.name}` ({size_mb:.2f} MB)...", parse_mode=ParseMode.MARKDOWN)
    try:
        ext = file_path.suffix.lower()
        with open(file_path, "rb") as f:
            if ext in [".png", ".jpg", ".jpeg", ".webp", ".gif"]:
                await update.message.reply_photo(photo=f, caption=f"🖼️ `{file_path.name}`", parse_mode=ParseMode.MARKDOWN)
            else:
                await update.message.reply_document(document=f, caption=f"📄 `{file_path.name}`", parse_mode=ParseMode.MARKDOWN)
        await status_msg.delete()
    except Exception as e:
        await status_msg.edit_text(f"❌ Failed to send file: {e}")

async def handle_document_upload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return
    state = get_state(update.effective_chat.id)
    cwd = Path(state["cwd"])

    doc = update.message.document
    photo = update.message.photo[-1] if update.message.photo else None

    if doc:
        file_name = doc.file_name or f"upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        tg_file = await doc.get_file()
    elif photo:
        file_name = f"photo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
        tg_file = await photo.get_file()
    else:
        return

    save_path = cwd / file_name
    status_msg = await update.message.reply_text(f"📥 Downloading `{file_name}` to active folder...", parse_mode=ParseMode.MARKDOWN)
    try:
        await tg_file.download_to_drive(custom_path=str(save_path))
        sz_kb = save_path.stat().st_size / 1024
        await status_msg.edit_text(f"✅ Saved `{file_name}` ({sz_kb:.1f} KB) to:\n`{save_path}`", parse_mode=ParseMode.MARKDOWN)
    except Exception as e:
        await status_msg.edit_text(f"❌ Failed to save file: {e}")

# PowerShell Shell Execution
async def run_shell_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return

    cmd = " ".join(context.args) if context.args else ""
    if not cmd:
        await update.message.reply_text("Usage: `/run <powershell command>`", parse_mode=ParseMode.MARKDOWN)
        return

    chat_id = update.effective_chat.id
    state = get_state(chat_id)
    cwd = state["cwd"]

    status_msg = await update.message.reply_text(f"⚡ Executing in `{cwd}`:\n`{cmd}`", parse_mode=ParseMode.MARKDOWN)

    try:
        proc = await asyncio.create_subprocess_shell(
            f"powershell -NoProfile -Command \"{cmd}\"",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )
        active_subprocesses[chat_id] = proc

        stdout, stderr = await proc.communicate()
        out = stdout.decode("utf-8", errors="replace").strip()
        err = stderr.decode("utf-8", errors="replace").strip()

        result = ""
        if out:
            result += f"**Output:**\n```\n{out}\n```\n"
        if err:
            result += f"**Errors:**\n```\n{err}\n```\n"
        if not result:
            result = "✅ Process finished with no output."

        result += f"\n*Exit Code: {proc.returncode}*"
        await status_msg.delete()
        await send_long_message(update.message, result, parse_mode=ParseMode.MARKDOWN)

    except Exception as e:
        await status_msg.edit_text(f"❌ Execution error: {e}")
    finally:
        active_subprocesses.pop(chat_id, None)

# Agent Execution Dispatcher -> Forwards prompt directly to Antigravity IDE
async def run_agent(update: Update, prompt: str):
    if not await check_auth(update):
        return

    chat_id = update.effective_chat.id
    conv_id = get_active_conversation_id(chat_id)

    # 1. Safely send acknowledgement on Telegram
    esc_prompt = html.escape(prompt[:140])
    esc_conv = html.escape(conv_id[:8])
    status_msg = None
    try:
        status_msg = await update.message.reply_text(
            f"📨 <b>Sent to Antigravity IDE</b>\n"
            f"💬 Prompt: <i>{esc_prompt}</i>\n"
            f"🆔 Session: <code>{esc_conv}...</code>\n\n"
            f"⚡ Processing inside the IDE now...",
            parse_mode=ParseMode.HTML
        )
    except Exception as e:
        logger.warning(f"Failed to send HTML ack, trying plain text: {e}")
        try:
            status_msg = await update.message.reply_text(
                f"📨 Sent to Antigravity IDE:\n\"{prompt[:100]}\"..."
            )
        except Exception:
            pass

    async def report_failure(text: str):
        logger.error(text)
        if status_msg:
            try:
                await status_msg.edit_text(text)
            except Exception:
                pass

    # 2. Post the prompt into the IDE chat as a user message, with the model chosen in Telegram
    ide_prompt = (f"{prompt}\n\n[From Telegram. Your final reply is relayed to Telegram automatically; "
                  f"don't send it yourself with notify_telegram.py.]")
    try:
        await ide_send_message(conv_id, ide_prompt, get_state(chat_id).get("model"))
        logger.info(f"Sent Telegram prompt to Antigravity IDE ({conv_id})")
    except IDEUnavailable as e:
        await report_failure(f"❌ {e}")
    except Exception as e:
        await report_failure(f"❌ Could not send to Antigravity IDE: {e}")

async def conv_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Pick which Antigravity IDE chat Telegram messages go to."""
    if not await check_auth(update):
        return
    chat_id = update.effective_chat.id
    state = get_state(chat_id)
    if context.args:
        arg = context.args[0].strip()
        state["conversation_id"] = "auto" if arg.lower() in ("auto", "latest") else arg
        save_state()
    active = get_active_conversation_id(chat_id)
    try:
        keyboard = await get_conversations_inline_keyboard(active)
    except IDEUnavailable as e:
        await update.message.reply_text(f"❌ {html.escape(str(e))}")
        return
    await update.message.reply_text(
        f"🗂️ <b>Antigravity IDE chats</b>\nActive: <code>{active[:8]}...</code>\n"
        f"Tap a chat to send your Telegram messages there:",
        parse_mode=ParseMode.HTML,
        reply_markup=keyboard,
    )

async def kill_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Stop a running /run shell command, or else the IDE agent's current run."""
    if not await check_auth(update):
        return
    chat_id = update.effective_chat.id
    proc = active_subprocesses.get(chat_id)
    if proc:
        try:
            proc.terminate()
            await update.message.reply_text("🛑 Shell command terminated.")
        except Exception as e:
            await update.message.reply_text(f"Error terminating process: {e}")
        return
    conv_id = get_active_conversation_id(chat_id)
    try:
        await ide_stop(conv_id)
        await update.message.reply_text(f"🛑 Stopped the IDE agent in chat <code>{conv_id[:8]}...</code>",
                                        parse_mode=ParseMode.HTML)
    except IDEUnavailable as e:
        await update.message.reply_text(f"❌ {html.escape(str(e))}")

# ==========================================
# BUTTON & CALLBACK ROUTING
# ==========================================

async def handle_callback_query(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    user = query.from_user
    if not is_authorized(user):
        await query.message.reply_text("⛔ Unauthorized.")
        return

    chat_id = query.message.chat_id
    state = get_state(chat_id)
    data = query.data

    if data.startswith("model:"):
        model_id = data.split(":", 1)[1]
        state["model"] = model_id
        save_state()
        await query.edit_message_text(
            f"✅ **Active Model switched to:** `{model_id}`\nTap below to change again:",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=await get_model_inline_keyboard(model_id)
        )

    elif data.startswith("proj:"):
        key = data.split(":", 1)[1]
        if key in QUICK_PROJECTS:
            new_path = QUICK_PROJECTS[key][0]
            state["cwd"] = new_path
            save_state()
            inline_kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("📂 Browse Files", callback_data="browse:cwd"),
                 InlineKeyboardButton("📑 Change Folder", callback_data="action:projects")]
            ])
            await query.edit_message_text(
                f"📂 **Switched to:** `{new_path}`\n\nWhat would you like to do?",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=inline_kb
            )

    elif data == "browse:cwd":
        target = Path(state["cwd"])
        items = list(target.iterdir()) if target.exists() else []
        dirs = sorted([d for d in items if d.is_dir()], key=lambda x: x.name.lower())[:20]
        files = sorted([f for f in items if f.is_file()], key=lambda x: x.name.lower())[:25]

        lines = [f"📂 **Files in:** `{target}`\n━━━━━━━━━━━━━━━━━━━━"]
        for d in dirs:
            lines.append(f"📁 `{d.name}/`")
        for f in files:
            sz = f.stat().st_size
            sz_str = f"{sz / 1024:.1f} KB" if sz > 1024 else f"{sz} B"
            lines.append(f"📄 `{f.name}` ({sz_str})")

        lines.append(f"\nTotal: `{len(dirs)} folders`, `{len(files)} files`")
        inline_kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("📑 Switch Project", callback_data="action:projects"),
             InlineKeyboardButton("⬆️ Up Folder", callback_data="browse:up")]
        ])
        await query.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN, reply_markup=inline_kb)

    elif data == "browse:up":
        parent = Path(state["cwd"]).parent
        if parent.exists() and parent.is_dir():
            state["cwd"] = str(parent)
            save_state()
            await query.message.reply_text(f"📂 Moved up to:\n`{parent}`", parse_mode=ParseMode.MARKDOWN)

    elif data == "action:screenshot":
        try:
            attach_to_user_desktop()
            img = ImageGrab.grab()
            bio = BytesIO()
            bio.name = "screenshot.jpg"
            img.save(bio, "JPEG", quality=85, optimize=True)
            bio.seek(0)
            inline_kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("🔄 Retake", callback_data="action:screenshot"),
                 InlineKeyboardButton("🖥️ Stats", callback_data="refresh:status")]
            ])
            await query.message.reply_photo(photo=bio, caption="🖥️ Current Desktop Screen", reply_markup=inline_kb)
        except Exception as e:
            await query.message.reply_text(f"⚠️ Screenshot note: {e}\n(Display is asleep or locked; terminal commands work normally).")

    elif data == "refresh:status":
        text = build_status_text(chat_id)
        inline_kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔄 Refresh Stats", callback_data="refresh:status"),
             InlineKeyboardButton("📸 Take Screenshot", callback_data="action:screenshot")],
            [InlineKeyboardButton("📊 View Token Quota", callback_data="action:quota")]
        ])
        try:
            await query.edit_message_text(text, parse_mode=ParseMode.MARKDOWN, reply_markup=inline_kb)
        except Exception:
            pass

    elif data == "action:quota":
        status_msg = await query.message.reply_text("📊 Checking token quota and rate limits...")
        text = await build_quota_text()
        inline_kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔄 Refresh Quota", callback_data="action:quota"),
             InlineKeyboardButton("🧠 Change Model", callback_data="action:models")]
        ])
        try:
            await status_msg.edit_text(text, parse_mode=ParseMode.HTML, reply_markup=inline_kb)
        except Exception:
            try:
                await status_msg.edit_text(text, parse_mode=ParseMode.MARKDOWN, reply_markup=inline_kb)
            except Exception:
                await status_msg.edit_text(text, reply_markup=inline_kb)

    elif data == "action:models":
        msg = f"🧠 **AI Model Selection**\nCurrently active: `{state['model']}`\nTap a button to switch:"
        await query.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, reply_markup=await get_model_inline_keyboard(state["model"]))

    elif data == "action:projects":
        msg = f"📑 **Project & Folder Manager**\nCurrent Folder: `{state['cwd']}`\nTap to switch:"
        await query.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN, reply_markup=get_projects_inline_keyboard())

    elif data == "action:reset":
        await query.message.reply_text(await start_new_ide_chat(chat_id), parse_mode=ParseMode.HTML)

    elif data.startswith("conv:"):
        choice = data.split(":", 1)[1]
        state["conversation_id"] = choice
        save_state()
        active = get_active_conversation_id(chat_id)
        mode = "Following the latest IDE chat" if choice == "auto" else "Telegram messages now go to this IDE chat"
        try:
            await query.edit_message_text(
                f"🗂️ <b>{mode}</b>\nActive: <code>{active[:8]}...</code>",
                parse_mode=ParseMode.HTML,
                reply_markup=await get_conversations_inline_keyboard(active),
            )
        except IDEUnavailable as e:
            await query.message.reply_text(f"❌ {html.escape(str(e))}")

    # Git Callbacks
    elif data == "git:status":
        cwd = state["cwd"]
        status_raw = os.popen(f'git -C "{cwd}" status').read().strip()
        await query.message.reply_text(f"📊 **Git Status:**\n```\n{status_raw}\n```", parse_mode=ParseMode.MARKDOWN)

    elif data == "git:diff":
        cwd = state["cwd"]
        diff_raw = os.popen(f'git -C "{cwd}" diff').read().strip()
        if not diff_raw:
            await query.message.reply_text("✨ No unstaged git diffs in active folder.")
        else:
            await send_long_message(query.message, f"🔍 **Git Diff:**\n```diff\n{diff_raw}\n```", parse_mode=ParseMode.MARKDOWN)

    elif data == "git:pull":
        cwd = state["cwd"]
        pull_raw = os.popen(f'git -C "{cwd}" pull').read().strip()
        await query.message.reply_text(f"🔄 **Git Pull:**\n```\n{pull_raw}\n```", parse_mode=ParseMode.MARKDOWN)

    elif data == "git:push":
        cwd = state["cwd"]
        status_msg = await query.message.reply_text("🚀 Running `git push`...")
        proc = await asyncio.create_subprocess_shell("git push", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=cwd)
        stdout, stderr = await proc.communicate()
        out = stdout.decode("utf-8", errors="replace").strip()
        err = stderr.decode("utf-8", errors="replace").strip()
        await status_msg.edit_text(f"🚀 **Git Push Output:**\n```\n{out or err or 'Everything up to date.'}\n```", parse_mode=ParseMode.MARKDOWN)

    elif data == "git:quick_commit":
        cwd = state["cwd"]
        c_msg = f"Auto-commit by Antigravity ({datetime.now().strftime('%H:%M:%S')})"
        os.popen(f'git -C "{cwd}" add -A').read()
        res = os.popen(f'git -C "{cwd}" commit -m "{c_msg}"').read().strip()
        inline_kb = InlineKeyboardMarkup([[InlineKeyboardButton("🚀 Push Now", callback_data="git:push")]])
        await query.message.reply_text(f"📝 **Committed:**\n```\n{res}\n```", parse_mode=ParseMode.MARKDOWN, reply_markup=inline_kb)

    elif data == "git:prompt_clone":
        await query.message.reply_text("To clone a repository into your active folder, type:\n`/clone <github_repo_url>`", parse_mode=ParseMode.MARKDOWN)

# Bottom Keyboard Text Handler
async def handle_bottom_button_press(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return

    text = update.message.text.strip()
    chat_id = update.effective_chat.id

    if text == "📊 Quota & Tokens":
        await usage_command(update, context)
    elif text == "🖥️ System Status":
        await status_command(update, context)
    elif text == "📸 Screenshot":
        await screen_command(update, context)
    elif text == "📂 Files & Projects":
        await projects_command(update, context)
    elif text == "🐙 Git & GitHub":
        await git_command_menu(update, context)
    elif text == "🧠 Switch Model":
        await model_command(update, context)
    elif text == "🗂️ IDE Chats":
        await conv_command(update, context)
    elif text == "🛑 Stop Agent":
        await kill_command(update, context)
    elif text == "🔄 Reset Agent":
        await new_conv_command(update, context)
    elif text == "❓ Help & Commands":
        await start_command(update, context)
    else:
        # Natural language prompt -> Autonomous Antigravity agent execution!
        await run_agent(update, text)

# ==========================================

# ==========================================
# WHISPER VOICE TRANSCRIPTION & LIVE TELEMETRY
# ==========================================
# WHISPER VOICE TRANSCRIPTION & LIVE TELEMETRY
# ==========================================

async def handle_voice_upload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await check_auth(update):
        return

    voice = update.message.voice or update.message.audio
    if not voice:
        return

    chat_id = update.effective_chat.id
    status_msg = await update.message.reply_text(
        "🎙️ **Transcribing voice note with local Whisper AI...**",
        parse_mode=ParseMode.MARKDOWN
    )

    import uuid
    from transcribe_audio import transcribe_audio_file

    temp_audio = BASE_DIR / f"voice_{uuid.uuid4().hex[:8]}.ogg"
    try:
        tg_file = await voice.get_file()
        await tg_file.download_to_drive(custom_path=str(temp_audio))

        loop = asyncio.get_running_loop()
        transcription = await loop.run_in_executor(None, transcribe_audio_file, str(temp_audio))

        if not transcription:
            await status_msg.edit_text("⚠️ No audible speech detected in the voice note.")
            return

        esc_trans = html.escape(transcription)
        try:
            await status_msg.edit_text(
                f"🎙️ <b>Voice Note Transcribed:</b>\n<i>{esc_trans}</i>\n\n🚀 <b>Forwarding to Antigravity IDE...</b>",
                parse_mode=ParseMode.HTML
            )
        except Exception:
            try:
                await status_msg.edit_text(f"🎙️ Transcribed: {transcription[:120]}...\nForwarding to IDE...")
            except Exception:
                pass

        await run_agent(update, transcription)

    except Exception as e:
        logger.error(f"Voice transcription failed: {e}")
        try:
            await status_msg.edit_text(f"❌ Voice transcription failed: {e}")
        except Exception:
            pass
    finally:
        if temp_audio.exists():
            try:
                temp_audio.unlink()
            except Exception:
                pass

async def transcript_monitor(application: Application):
    """Background monitor: streams completed agent responses from transcript.jsonl back to Telegram."""
    logger.info("Starting live transcript monitor for Antigravity IDE responses...")
    # Step indexes are per conversation; the active conversation can change while running.
    last_step_index: dict[str, int] = {}
    agent_notified: dict[str, bool] = {}
    last_ide_refresh = 0.0

    def read_steps(path: Path) -> list[dict]:
        steps = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.strip():
                try:
                    steps.append(json.loads(line))
                except Exception:
                    pass
        return steps

    while True:
        try:
            await asyncio.sleep(1.5)
            if time.monotonic() - last_ide_refresh > 10:
                last_ide_refresh = time.monotonic()
                try:
                    await refresh_latest_user_conversation()
                except IDEUnavailable:
                    pass
            # Follow the chat picked from Telegram (/conv), like run_agent does
            primary_chat = int(os.getenv("TELEGRAM_CHAT_ID", "0") or 0) or None
            conv_id = get_active_conversation_id(primary_chat)
            transcript_path = (Path.home() / ".gemini" / "antigravity-ide" / "brain" / conv_id /
                               ".system_generated" / "logs" / "transcript.jsonl")
            if not transcript_path.exists():
                continue

            steps = read_steps(transcript_path)
            if conv_id not in last_step_index:
                # First time seeing this conversation: skip its history, only stream new responses
                last_step_index[conv_id] = max((s.get("step_index", -1) for s in steps), default=-1)
                logger.info(f"Transcript monitor tracking {conv_id[:8]} from step_index={last_step_index[conv_id]}")
                continue

            for data in steps:
                idx = data.get("step_index", -1)
                if idx <= last_step_index[conv_id]:
                    continue

                last_step_index[conv_id] = idx

                # The agent sometimes messages Telegram itself via notify_telegram.py.
                # Remember that per turn so its final response isn't relayed a second time.
                if data.get("type") == "USER_INPUT" or (
                        data.get("type") == "SYSTEM_MESSAGE" and "[Message]" in str(data.get("content", ""))):
                    agent_notified[conv_id] = False
                if "notify_telegram" in json.dumps(data.get("tool_calls") or []):
                    agent_notified[conv_id] = True

                # Final agent response turn to user
                if (data.get("source") == "MODEL" and
                    data.get("type") == "PLANNER_RESPONSE" and
                    data.get("status") == "DONE" and
                    data.get("content")):

                    content = data["content"].strip()
                    if not content:
                        continue
                    if agent_notified.pop(conv_id, False):
                        logger.info(f"Skipping relay of step {idx}: agent already messaged Telegram this turn")
                        continue

                    target_chats = [cid for cid in whitelisted_ids if cid != 12345678]
                    if not target_chats and os.getenv("TELEGRAM_CHAT_ID"):
                        target_chats = [int(os.getenv("TELEGRAM_CHAT_ID"))]

                    for cid in target_chats:
                        try:
                            MAX_LEN = 3900
                            for i in range(0, len(content), MAX_LEN):
                                chunk = content[i:i + MAX_LEN]
                                try:
                                    await application.bot.send_message(chat_id=cid, text=chunk, parse_mode=ParseMode.MARKDOWN)
                                except Exception:
                                    await application.bot.send_message(chat_id=cid, text=chunk)
                        except Exception as e:
                            logger.error(f"Failed to stream response to chat {cid}: {e}")

        except Exception as e:
            logger.error(f"Error in transcript_monitor: {e}")
            await asyncio.sleep(3)

# MAIN APPLICATION
# ==========================================

def main():
    logger.info("Initializing Antigravity Mobile Workstation Telegram Daemon...")
    async def on_startup(app: Application):
        asyncio.create_task(transcript_monitor(app))

    application = Application.builder().token(BOT_TOKEN).post_init(on_startup).build()

    # Commands
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("sys", status_command))
    application.add_handler(CommandHandler("screen", screen_command))
    application.add_handler(CommandHandler("usage", usage_command))
    application.add_handler(CommandHandler("quota", usage_command))
    application.add_handler(CommandHandler("tokens", usage_command))
    application.add_handler(CommandHandler("projects", projects_command))
    application.add_handler(CommandHandler("pwd", pwd_command))
    application.add_handler(CommandHandler("cd", cd_command))
    application.add_handler(CommandHandler("ls", ls_command))
    application.add_handler(CommandHandler("model", model_command))
    application.add_handler(CommandHandler("models", model_command))
    application.add_handler(CommandHandler("new", new_conv_command))
    application.add_handler(CommandHandler("reset", new_conv_command))
    application.add_handler(CommandHandler("get", get_file_command))
    application.add_handler(CommandHandler("run", run_shell_command))
    application.add_handler(CommandHandler("kill", kill_command))
    application.add_handler(CommandHandler("conv", conv_command))
    application.add_handler(CommandHandler("chats", conv_command))
    application.add_handler(CommandHandler("stop", kill_command))

    # Git Commands
    application.add_handler(CommandHandler("git", raw_git_command))
    application.add_handler(CommandHandler("clone", clone_command))
    application.add_handler(CommandHandler("diff", diff_command))
    application.add_handler(CommandHandler("commit", commit_command))
    application.add_handler(CommandHandler("push", push_command))
    application.add_handler(CommandHandler("pull", pull_command))

    # Media / File Uploads
    application.add_handler(MessageHandler(filters.VOICE | filters.AUDIO, handle_voice_upload))
    application.add_handler(MessageHandler(filters.Document.ALL | filters.PHOTO, handle_document_upload))

    # Inline Callbacks
    application.add_handler(CallbackQueryHandler(handle_callback_query))

    # Bottom Keyboard & Natural Text Messages
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_bottom_button_press))

    
    async def global_error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
        if isinstance(context.error, telegram.error.Conflict):
            logger.warning("Telegram conflict detected (handover active). Poller will auto-retry...")
            await asyncio.sleep(4)
            return
        logger.error("Exception in update handler:", exc_info=context.error)

    application.add_error_handler(global_error_handler)

    logger.info("Bot starting in long-polling mode (authorized for @%s)...", ALLOWED_USERNAME)
    application.run_polling(drop_pending_updates=False)

if __name__ == "__main__":
    main()
