# SideBar Assistant

SideBar Assistant is a frameless, always-on-top sidebar application built with PySide6. It integrates a smart “assistant” chat interface (powered by an Open WebUI backend), Google web search, YouTube transcript extraction, local notes, clipboard history, process monitoring, and optional peer-to-peer synchronization with end-to--end encryption.

---

## Features

- **Auto-hiding Sidebar**  
  The window docks to the right edge of the screen and auto-hides when the mouse moves away, making it available on demand without cluttering your workspace. citeturn1file1

- **Clipboard History**  
  Monitors your clipboard and keeps up to 30 items; navigate, search, and re-paste previous entries. citeturn1file4

- **Notes Pane**  
  A simple notepad for quick text notes. Notes are auto-saved every 5 seconds when modified. citeturn1file4

- **Process Monitor**  
  Displays a live list of running processes and highlights critical system processes. citeturn1file8

- **Assistant Chat Widget**  
  - **Open WebUI Integration**: Connect to a locally running Open WebUI endpoint, fetch available models, and stream chat completions. citeturn1file15  
  - **Web Search**: Query the Google Custom Search API (requires API key and CX) and embed results into the chat. citeturn1file7  
  - **YouTube Transcripts**: Detect YouTube links in your prompt, fetch transcripts via the YouTube Transcript API (Korean first, then English fallback), and include them in the conversation. citeturn1file7  
  - **File Uploads**: Drag-and-drop or browse to upload text (txt, md, csv, code), images, and other binaries; content is encoded and appended to the prompt. citeturn1file6

- **P2P Synchronization (Experimental)**  
  - Peer-to-peer sharing of notes, clipboard, or other data with optional AES-GCM encryption using PBKDF2-derived keys.  
  - Salt-exchange and mutual authentication protocol ensure secure key negotiation.  
  - Manage peers (IP:port), toggle encryption, and set credentials in Settings. citeturn1file4

- **Configurable Settings**  
  All features are customizable via a unified Settings dialog:  
  - Notes directory  
  - P2P sync (enable/disable, encryption toggle, username/password, peer list)  
  - Open WebUI endpoint, API key, and model selection  
  - Google Search API key and Custom Search Engine ID  
  - Window behavior (auto-hide, always-on-top) citeturn1file15

- **Robust Logging**  
  Logs are written to a rotating file (5 MB max, 5 backups) under `log/`; debug, info, warning, and error events are captured. citeturn1file8

---

## Installation

1. **Clone the repository**  
   ```bash
   git clone https://github.com/yourusername/sidebar-assistant.git
   cd sidebar-assistant
   ```

2. **Create a virtual environment & install dependencies**  
   ```bash
   python3 -m venv venv
   source venv/bin/activate    # Windows: venv\Scripts\activate
   pip install --upgrade pip
   pip install PySide6 requests google-api-python-client youtube-transcript-api validators cryptography psutil
   ```

3. **Configure Settings**  
   - Run the app once to generate default config and notes directory.  
   - Open Settings (tray icon ➔ Settings) to enter your API keys, WebUI endpoint, and P2P peers.

---

## Usage

```bash
python main_4.py
```

- The app will appear as a thin sidebar on the right.  
- Hover near the right edge to reveal, move away to hide (if auto-hide is enabled).  
- Use the tabs to switch between Clipboard, Processes, Notes, and Assistant.

---

## Configuration

Launch Settings from the system tray menu:

1. **General**  
   - **Notes Directory**: Location where your notes are stored.

2. **P2P Synchronization**  
   - Enable or disable P2P.  
   - Toggle encryption (AES-GCM).  
   - Set Username & Password (used for key derivation).  
   - Specify Listen Port and peer addresses (IP:port).

3. **Open WebUI Assistant**  
   - **Endpoint URL**: e.g. `http://localhost:8080`  
   - **API Key** (if your WebUI instance requires authentication)  
   - **Model**: Fetch and select from available models on the WebUI server.

4. **Google Search API**  
   - **Google API Key**  
   - **Custom Search Engine ID (CX)**

5. **Window**  
   - Auto-hide toggle  
   - Always-on-top toggle

---

## Project Structure

- **`main_4.py`**: Single-file application containing all logic: GUI, P2P manager, WebUI worker, and helper functions.  
- **`log/`**: Directory for rotating application logs.  
- **`Notes/`**: Default directory under your OS’s AppData for saving notes.

---

## License

This project is released under the MIT License. Feel free to fork and modify!
