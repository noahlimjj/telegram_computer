# Antigravity Mobile Workstation (Telegram Bot)

Turn your phone into a remote developer terminal for your PC with autonomous Antigravity agents.

---

## 🚀 Quick Launch

* **Interactive window**: Double-click `start_bot.bat`
* **Silent 24/7 background mode**: Double-click `start_silent.vbs`
* **Auto-start on Windows Boot**: Press `Win + R`, type `shell:startup`, and create a shortcut to `start_silent.vbs`.

---

## 📱 Mobile Telegram Interface

### 1. Natural Language Autonomous Agent
Any plain message sent from your phone runs an autonomous **Antigravity CLI** agent inside your current folder on your PC with auto-approved permissions (`--dangerously-skip-permissions`).
* Example: *"Fix the bug in utils.py where date parsing fails and add tests"*
* Example: *"Scrape the top 5 articles from this URL and save them to a markdown file"*
* Example: *"Refactor the database connection to use pooling"*

### 2. GitHub & Git Integration
* `/clone <repo_url> [folder]` - Clones a GitHub repo and automatically sets it as the active working directory.
* `/diff` - Shows full git diff of changes made by Antigravity.
* `/commit <message>` - Stages all changes and commits.
* `/push` - Pushes commits to GitHub.
* `/pull` - Pulls latest remote commits.
* `/git <subcommand>` - Runs any raw git command (e.g. `/git log -n 5`, `/git branch`).

### 3. File & Project Navigation
* Tap **`📂 Files & Projects`** or use `/projects` to jump between `Home`, `D:\`, `Desktop`, `Downloads`, `Scratch`, and custom projects.
* `/cd <path>` - Changes the working directory.
* `/ls [path]` - Lists files and folders with sizes.
* `/pwd` - Shows active folder and disk space.
* `/get <filename>` - Uploads a file from your PC to Telegram so you can view it on your phone.
* **Send any file/photo to the bot**: Saves directly into your active folder on PC.

### 4. Quota & Token Monitoring
* Tap **`📊 Quota & Tokens`** or use `/usage`:
  - Renders visual progress bars for Gemini Weekly (42%) and 5-Hour (67%) quotas.
  - Shows reset dates/times.
  - Reports token usage for every prompt turn.

### 5. Hardware & Shell Execution
* Tap **`🖥️ System Status`** or `/sys`: CPU load, RAM usage, disk space, and RTX 3070 GPU temp/VRAM.
* Tap **`📸 Screenshot`** or `/screen`: Captures full desktop screen and sends photo.
* `/run <powershell>` - Runs any PowerShell command on your PC.
* `/kill` - Terminates any running agent or subprocess.

### 6. Model Selection
* Tap **`🧠 Switch Model`** or `/model`:
  - `gemini-3.8-flash-high`
  - `claude-sonnet-4-6`
  - `claude-opus-4-6-thinking`
  - `gpt-oss-120b-medium`
* `/new` - Clears conversation memory for a clean turn.


### 7. Voice Notes & Audio Transcription (Whisper AI)
* Hold the mic button in Telegram to send any voice note or prompt.
* Transcribes speech locally with high-speed **Whisper AI** (aster-whisper), runs the agent, and streams the agent's completed answers straight back to Telegram in real-time.

---

## 🛠️ Setup & Configuration

1. Clone the repository:
   `ash
   git clone https://github.com/noahlimjj/telegram_computer.git
   cd telegram_computer
   `
2. Install dependencies:
   `ash
   pip install -r requirements.txt
   `
3. Copy .env.example to .env and fill in your details:
   `ash
   copy .env.example .env
   `
   - Obtain TELEGRAM_BOT_TOKEN from [@BotFather](https://t.me/BotFather).
   - Set ALLOWED_USERNAME to your Telegram username.
4. Launch the daemon:
   - Double-click start_bot.bat or run python bot.py.
