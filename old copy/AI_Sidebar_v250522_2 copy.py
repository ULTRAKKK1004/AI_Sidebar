import sys
import os
import psutil
import re
import base64
import json
import requests
import socket
import threading
import time
import hashlib
import hmac
import logging
import logging.handlers
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# 추가 라이브러리
from youtube_transcript_api import YouTubeTranscriptApi
from googleapiclient.discovery import build
import validators

# 마크다운 지원을 위한 라이브러리 추가
import markdown
from markdownify import markdownify as md
import markdown.extensions.fenced_code
import markdown.extensions.tables
import markdown.extensions.nl2br
import markdown.extensions.codehilite
from markdown.extensions.toc import TocExtension

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QTabWidget, QLabel,
    QTextEdit, QListWidget, QPushButton, QLineEdit, QHBoxLayout, QSplitter,
    QListWidgetItem, QMessageBox, QInputDialog, QFileDialog, QAbstractItemView,
    QSystemTrayIcon, QMenu, QDialog, QFormLayout, QDialogButtonBox,
    QGroupBox, QTabBar, QCheckBox, QComboBox, QPlainTextEdit, QProgressBar,
    QToolButton, QSizePolicy, QTextBrowser
)
from PySide6.QtCore import (
    Qt, QTimer, QSettings, QSize, QMimeData, QDir, QStandardPaths, QRect,
    QByteArray, QBuffer, QIODevice, Signal, QObject, QThread, Slot, QEvent,
    QMetaObject, Q_ARG, QPoint, QUrl
)
from PySide6.QtGui import (
    QClipboard, QPixmap, QImage, QAction, QIcon, QGuiApplication, QCursor,
    QShortcut, QKeySequence, QScreen, QCloseEvent, QTextCursor, QPainter,
    QDrag, QDropEvent, QDragEnterEvent, QFont, QFontDatabase, QSyntaxHighlighter,
    QTextCharFormat, QColor
)

import platform

# --- Constants ---
MAX_CLIPBOARD_HISTORY = 30
if platform.system() == "Windows":
    CRITICAL_PROCESSES = [
        "system idle process", "system", "smss.exe", "csrss.exe",
        "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe",
        "explorer.exe"
    ]
elif platform.system() == "Linux":
    CRITICAL_PROCESSES = [
        "systemd", "kthreadd", "init", "dbus-daemon", "NetworkManager",
        "Xorg", "gnome-shell", "pulseaudio"
    ]
else:
    CRITICAL_PROCESSES = []
SETTINGS_ORG = "SideBar"
SETTINGS_APP = "SideBarAssistant"
SIDEBAR_WIDTH = 400
DEFAULT_P2P_PORT = 61101
SALT_SIZE = 16
PBKDF2_ITERATIONS = 390000
AES_KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
LOG_DIR = "log"
LOG_FILE_MAX_BYTES = 5 * 1024 * 1024
LOG_FILE_BACKUP_COUNT = 5
MAX_CONVERSATION_LENGTH = 2000  # 최대 대화 길이 (요약 전) 기존값 10
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB 파일 업로드 제한 기존값 10MB

# 전역 상수 정의
DEFAULT_WEBUI_ENDPOINT = os.getenv("DEFAULT_WEBUI_ENDPOINT", "http://localhost:8000")
DEFAULT_WEBUI_API_KEY = os.getenv("DEFAULT_WEBUI_API_KEY", "your api key")
DEFAULT_WEBUI_MODEL = os.getenv("DEFAULT_WEBUI_MODEL", "gpt-4o-mini")
Proxy_http = os.getenv("Proxy_http", "http://168.219.61.252:8080")
Proxy_https = os.getenv("Proxy_https", "http://168.219.61.252:8080")

# --- Setup Logging ---
def setup_logging():
    log_formatter = logging.Formatter("%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s")
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    try:
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)
        timestr = time.strftime("%Y-%m-%d")
        log_filename = os.path.join(LOG_DIR, f"{timestr}.log")
        file_handler = logging.handlers.RotatingFileHandler(log_filename, maxBytes=LOG_FILE_MAX_BYTES, backupCount=LOG_FILE_BACKUP_COUNT, encoding="utf-8")
        file_handler.setFormatter(log_formatter)
        logger.addHandler(file_handler)
        logging.info("Logging initialized.")
    except Exception as e:
        print(f"Error setting up file logging: {e}")

setup_logging()

# --- Markdown Highlighter Class ---
class MarkdownHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # Headers
        header_format = QTextCharFormat()
        header_format.setFontWeight(QFont.Bold)
        header_format.setForeground(QColor("#0066CC"))
        self.highlighting_rules.append(("^#\\s+.+$", header_format))
        self.highlighting_rules.append(("^##\\s+.+$", header_format))
        self.highlighting_rules.append(("^###\\s+.+$", header_format))
        self.highlighting_rules.append(("^####\\s+.+$", header_format))
        self.highlighting_rules.append(("^#####\\s+.+$", header_format))
        self.highlighting_rules.append(("^######\\s+.+$", header_format))
        
        # Bold
        bold_format = QTextCharFormat()
        bold_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append(("\\*\\*[^\\*]+\\*\\*", bold_format))
        self.highlighting_rules.append(("__[^_]+__", bold_format))
        
        # Italic
        italic_format = QTextCharFormat()
        italic_format.setFontItalic(True)
        self.highlighting_rules.append(("\\*[^\\*]+\\*", italic_format))
        self.highlighting_rules.append(("_[^_]+_", italic_format))
        
        # Code
        code_format = QTextCharFormat()
        code_format.setFontFamily("Courier New")
        code_format.setBackground(QColor("#F0F0F0"))
        self.highlighting_rules.append(("`[^`]+`", code_format))
        
        # Links
        link_format = QTextCharFormat()
        link_format.setForeground(QColor("#0000FF"))
        link_format.setFontUnderline(True)
        self.highlighting_rules.append(("\\[.+\\]\\(.+\\)", link_format))
        
        # Lists
        list_format = QTextCharFormat()
        list_format.setForeground(QColor("#990000"))
        self.highlighting_rules.append(("^\\s*[-*+]\\s+.+$", list_format))
        self.highlighting_rules.append(("^\\s*\\d+\\.\\s+.+$", list_format))
        
        # Block quotes
        quote_format = QTextCharFormat()
        quote_format.setForeground(QColor("#808080"))
        quote_format.setFontItalic(True)
        self.highlighting_rules.append(("^>\\s+.+$", quote_format))
        
        # Code blocks
        code_block_format = QTextCharFormat()
        code_block_format.setFontFamily("Courier New")
        code_block_format.setBackground(QColor("#F5F5F5"))
        self.code_block_start = re.compile("^```.*$")
        self.code_block_end = re.compile("^```$")
        self.in_code_block = False
        self.code_block_format = code_block_format

    def highlightBlock(self, text):
        # 코드 블록 처리
        if self.in_code_block:
            self.setFormat(0, len(text), self.code_block_format)
            if self.code_block_end.match(text):
                self.in_code_block = False
            return
        
        if self.code_block_start.match(text):
            self.setFormat(0, len(text), self.code_block_format)
            self.in_code_block = True
            return
        
        # 다른 마크다운 문법 처리
        for pattern, format in self.highlighting_rules:
            expression = re.compile(pattern)
            matches = expression.finditer(text)
            for match in matches:
                start = match.start()
                length = match.end() - match.start()
                self.setFormat(start, length, format)

# --- 마크다운 노트 에디터 ---
class MarkdownEditor(QWidget):
    text_changed_signal = Signal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # 에디터와 미리보기 전환 툴바
        toolbar = QHBoxLayout()
        
        self.edit_mode_btn = QPushButton("Editor")
        self.edit_mode_btn.setCheckable(True)
        self.edit_mode_btn.setChecked(True)
        
        self.preview_mode_btn = QPushButton("Preview")
        self.preview_mode_btn.setCheckable(True)
        
        # 버튼 그룹 관리
        self.edit_mode_btn.clicked.connect(lambda: self.set_mode("edit"))
        self.preview_mode_btn.clicked.connect(lambda: self.set_mode("preview"))
        
        toolbar.addWidget(self.edit_mode_btn)
        toolbar.addWidget(self.preview_mode_btn)
        toolbar.addStretch()
        
        # 마크다운 형식 도구 버튼 추가
        self.bold_btn = QToolButton()
        self.bold_btn.setText("B")
        self.bold_btn.setToolTip("Bold")
        self.bold_btn.clicked.connect(lambda: self.insert_markdown_format("**", "**"))
        
        self.italic_btn = QToolButton()
        self.italic_btn.setText("I")
        self.italic_btn.setToolTip("Italic")
        self.italic_btn.clicked.connect(lambda: self.insert_markdown_format("*", "*"))
        
        self.code_btn = QToolButton()
        self.code_btn.setText("Code")
        self.code_btn.setToolTip("Inline Code")
        self.code_btn.clicked.connect(lambda: self.insert_markdown_format("`", "`"))
        
        self.link_btn = QToolButton()
        self.link_btn.setText("Link")
        self.link_btn.setToolTip("Insert Link")
        self.link_btn.clicked.connect(self.insert_link)
        
        self.image_btn = QToolButton()
        self.image_btn.setText("Image")
        self.image_btn.setToolTip("Insert Image")
        self.image_btn.clicked.connect(self.insert_image)
        
        self.header_btn = QToolButton()
        self.header_btn.setText("H")
        self.header_btn.setToolTip("Insert Header")
        self.header_btn.clicked.connect(lambda: self.insert_markdown_format("# ", ""))
        
        toolbar.addWidget(self.bold_btn)
        toolbar.addWidget(self.italic_btn)
        toolbar.addWidget(self.code_btn)
        toolbar.addWidget(self.link_btn)
        toolbar.addWidget(self.image_btn)
        toolbar.addWidget(self.header_btn)
        
        layout.addLayout(toolbar)
        
        # 에디터와 미리보기 위젯
        self.editor = QPlainTextEdit()
        self.editor.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.editor.textChanged.connect(self.text_changed)
        
        # 마크다운 하이라이터 적용
        self.highlighter = MarkdownHighlighter(self.editor.document())
        
        # 미리보기 브라우저
        self.preview = QTextBrowser()
        self.preview.setOpenExternalLinks(True)
        
        # 기본적으로 에디터 표시
        layout.addWidget(self.editor)
        layout.addWidget(self.preview)
        self.preview.hide()
        
        # 모노스페이스 폰트 적용
        font = QFont("Consolas, Courier New")
        font.setPointSize(10)
        self.editor.setFont(font)
    
    def set_mode(self, mode):
        if mode == "edit":
            self.edit_mode_btn.setChecked(True)
            self.preview_mode_btn.setChecked(False)
            self.editor.show()
            self.preview.hide()
            
            # 편집 관련 버튼 활성화
            self.bold_btn.setEnabled(True)
            self.italic_btn.setEnabled(True)
            self.code_btn.setEnabled(True)
            self.link_btn.setEnabled(True)
            self.image_btn.setEnabled(True)
            self.header_btn.setEnabled(True)
            
        elif mode == "preview":
            self.edit_mode_btn.setChecked(False)
            self.preview_mode_btn.setChecked(True)
            self.editor.hide()
            
            # 마크다운을 HTML로 변환하여 미리보기에 표시
            md_text = self.editor.toPlainText()
            html = self.markdown_to_html(md_text)
            self.preview.setHtml(html)
            self.preview.show()
            
            # 편집 관련 버튼 비활성화
            self.bold_btn.setEnabled(False)
            self.italic_btn.setEnabled(False)
            self.code_btn.setEnabled(False)
            self.link_btn.setEnabled(False)
            self.image_btn.setEnabled(False)
            self.header_btn.setEnabled(False)
    
    def markdown_to_html(self, md_text):
        extensions = [
            'markdown.extensions.fenced_code',
            'markdown.extensions.tables',
            'markdown.extensions.nl2br',
            'markdown.extensions.codehilite',
            TocExtension(baselevel=1)
        ]
        return markdown.markdown(md_text, extensions=extensions)
    
    def text_changed(self):
        self.text_changed_signal.emit()
    
    def toPlainText(self):
        return self.editor.toPlainText()
    
    def setPlainText(self, text):
        return self.editor.setPlainText(text)
    
    def insert_markdown_format(self, prefix, suffix):
        cursor = self.editor.textCursor()
        selected_text = cursor.selectedText()
        
        # 선택된 텍스트에 형식 적용
        if selected_text:
            cursor.insertText(f"{prefix}{selected_text}{suffix}")
        else:
            cursor.insertText(f"{prefix}text{suffix}")
            # 커서를 "text" 부분에 위치시킴
            cursor.movePosition(QTextCursor.Left, QTextCursor.MoveAnchor, len(suffix))
            cursor.movePosition(QTextCursor.Left, QTextCursor.KeepAnchor, 4)  # "text" 선택
        
        self.editor.setTextCursor(cursor)
        self.editor.setFocus()
    
    def insert_link(self):
        cursor = self.editor.textCursor()
        selected_text = cursor.selectedText()
        
        link_text = selected_text if selected_text else "link text"
        cursor.insertText(f"[{link_text}](https://example.com)")
        
        if not selected_text:
            # 링크 텍스트에 커서 위치
            cursor.movePosition(QTextCursor.Left, QTextCursor.MoveAnchor, 20)  # "https://example.com)" 길이
            cursor.movePosition(QTextCursor.Left, QTextCursor.KeepAnchor, 9)   # "link text" 선택
        
        self.editor.setTextCursor(cursor)
        self.editor.setFocus()
    
    def insert_image(self):
        cursor = self.editor.textCursor()
        cursor.insertText("![image description](image_url)")
        
        # 이미지 설명에 커서 위치
        cursor.movePosition(QTextCursor.Left, QTextCursor.MoveAnchor, 11)  # "image_url)" 길이
        cursor.movePosition(QTextCursor.Left, QTextCursor.KeepAnchor, 17)  # "image description" 선택
        
        self.editor.setTextCursor(cursor)
        self.editor.setFocus()

# --- YouTube Transcript Helper ---
def get_youtube_transcript(video_id,**kwargs):
    '''
    kwargs:
        proxy_disabled: bool, default=True
        Proxy_http: str, default="http://168.219.61.252:8080"
        Proxy_https: str, default="http://168.219.61.252:8080"
    '''
    proxy_disabled = kwargs.get("proxy_disabled", True)
    if proxy_disabled:
        try:
            transcript_list = YouTubeTranscriptApi.get_transcript(video_id,languages=("ko",))
            return " ".join([item['text'] for item in transcript_list])
        except Exception as e:
            logging.error(f"Error fetching YouTube transcript: {e}")
            try:
                transcript_list = YouTubeTranscriptApi.get_transcript(video_id,languages=("en",))
                return " ".join([item['text'] for item in transcript_list])
            except Exception as e:
                logging.error(f"Error fetching YouTube transcript: {e}")
                return f"Error fetching transcript: {str(e)}"
    else:
        Proxy_http = kwargs.get("Proxy_http", "http://168.219.61.252:8080")
        Proxy_https = kwargs.get("Proxy_https", "http://168.219.61.252:8080")
        try:
            transcript_list = YouTubeTranscriptApi.get_transcript(video_id,languages=("ko",),proxies={"http": Proxy_http, "https": Proxy_https},verify=False)
            return " ".join([item['text'] for item in transcript_list])
        except Exception as e:
            logging.error(f"Error fetching YouTube transcript: {e}")
            try:
                transcript_list = YouTubeTranscriptApi.get_transcript(video_id,languages=("en",),proxies={"http": Proxy_http, "https": Proxy_https},verify=False)
                return " ".join([item['text'] for item in transcript_list])
            except Exception as e:
                logging.error(f"Error fetching YouTube transcript: {e}")
                return f"Error fetching transcript: {str(e)}"
# --- Google Search Helper ---
def search_google(query, api_key, cx):
    try:
        service = build("customsearch", "v1", developerKey=api_key)
        result = service.cse().list(q=query, cx=cx, num=5).execute()
        
        search_results = []
        if "items" in result:
            for item in result["items"]:
                search_results.append({
                    "title": item.get("title", ""),
                    "link": item.get("link", ""),
                    "snippet": item.get("snippet", "")
                })
        
        return search_results
    except Exception as e:
        logging.error(f"Error performing Google search: {e}")
        return [{"title": "Error", "link": "", "snippet": f"Search error: {str(e)}"}]

# --- P2P Peer Class ---
class Peer:
    def __init__(self, address, port, status="Disconnected"):
        self.address = address
        self.port = int(port)
        self.status = status
        self.connection = None
        self.authenticated = False

    def __str__(self):
        return f"{self.address}:{self.port} [{self.status}]"

    def to_dict(self):
        return {"address": self.address, "port": self.port}

    @classmethod
    def from_dict(cls, data):
        return cls(data["address"], data["port"])

# --- Settings Dialog ---
class SettingsDialog(QDialog):
    settings_updated_signal = Signal()

    # 수정된 SettingsDialog 초기화 부분 (model_combo 부분 추가)
    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.setMinimumWidth(500)
        main_layout = QVBoxLayout(self)
        
        # General Settings
        general_group = QGroupBox("General")
        general_layout = QFormLayout(general_group)
        notes_dir_layout = QHBoxLayout()
        self.notes_dir_edit = QLineEdit()
        self.notes_dir_edit.setReadOnly(True)
        notes_browse_button = QPushButton("Browse...")
        notes_browse_button.clicked.connect(self.browse_notes_directory)
        notes_dir_layout.addWidget(self.notes_dir_edit)
        notes_dir_layout.addWidget(notes_browse_button)
        general_layout.addRow("Notes Directory:", notes_dir_layout)
        main_layout.addWidget(general_group)
        
        # P2P Settings
        p2p_group = QGroupBox("P2P Synchronization")
        p2p_layout = QFormLayout(p2p_group)
        self.p2p_enabled_checkbox = QCheckBox("Enable P2P Synchronization")
        p2p_layout.addRow(self.p2p_enabled_checkbox)
        # 암호화 선택 옵션 추가
        self.p2p_encryption_checkbox = QCheckBox("Enable Encryption")
        p2p_layout.addRow(self.p2p_encryption_checkbox)
        self.sync_user_edit = QLineEdit()
        p2p_layout.addRow("Username:", self.sync_user_edit)
        self.sync_pass_edit = QLineEdit()
        self.sync_pass_edit.setEchoMode(QLineEdit.Password)
        p2p_layout.addRow("Password:", self.sync_pass_edit)
        self.p2p_port_edit = QLineEdit()
        self.p2p_port_edit.setPlaceholderText(str(DEFAULT_P2P_PORT))
        p2p_layout.addRow("Listen Port:", self.p2p_port_edit)
        p2p_layout.addRow(QLabel("Peers (IP:Port):"))
        self.peer_list_widget = QListWidget()
        self.peer_list_widget.setSelectionMode(QAbstractItemView.SingleSelection)
        p2p_layout.addRow(self.peer_list_widget)
        peer_button_layout = QHBoxLayout()
        self.add_peer_button = QPushButton("Add Peer")
        self.remove_peer_button = QPushButton("Remove Peer")
        self.add_peer_button.clicked.connect(self.add_peer)
        self.remove_peer_button.clicked.connect(self.remove_peer)
        peer_button_layout.addWidget(self.add_peer_button)
        peer_button_layout.addWidget(self.remove_peer_button)
        p2p_layout.addRow(peer_button_layout)
        main_layout.addWidget(p2p_group)
        
        # WebUI Assistant Settings
        webui_group = QGroupBox("Open WebUI Assistant")
        webui_layout = QFormLayout(webui_group)
        self.webui_endpoint_edit = QLineEdit()
        self.webui_endpoint_edit.setPlaceholderText("http://localhost:8080")
        webui_layout.addRow("Endpoint URL:", self.webui_endpoint_edit)
        self.webui_apikey_edit = QLineEdit()
        self.webui_apikey_edit.setEchoMode(QLineEdit.Password)
        webui_layout.addRow("API Key (Optional):", self.webui_apikey_edit)
        
        # 프록시 예외 설정 추가 (수정사항 3)
        self.disable_proxy_checkbox = QCheckBox("Disable Proxy for AI Endpoint")
        self.disable_proxy_checkbox.setToolTip("Use direct connection without system proxy (helps with SSL issues)")
        webui_layout.addRow(self.disable_proxy_checkbox)
        
        # 모델 콤보박스 설정 부분 (누락된 부분)
        model_layout = QHBoxLayout()
        self.webui_model_combo = QComboBox()
        self.webui_model_combo.setMinimumWidth(200)
        fetch_models_button = QPushButton("Fetch Models")
        fetch_models_button.clicked.connect(self.fetch_webui_models)
        model_layout.addWidget(self.webui_model_combo)
        model_layout.addWidget(fetch_models_button)
        webui_layout.addRow("Model:", model_layout)
        
        main_layout.addWidget(webui_group)
        
        # Google Search API Settings
        google_api_group = QGroupBox("Google Search API")
        google_api_layout = QFormLayout(google_api_group)
        self.google_api_key_edit = QLineEdit()
        self.google_api_key_edit.setEchoMode(QLineEdit.Password)
        google_api_layout.addRow("Google API Key:", self.google_api_key_edit)
        self.google_cx_edit = QLineEdit()
        google_api_layout.addRow("Google Custom Search ID (CX):", self.google_cx_edit)
        main_layout.addWidget(google_api_group)
        
        # Dialog Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.save_and_close)
        button_box.rejected.connect(self.reject)
        main_layout.addWidget(button_box)
        
        self.load_settings_values()
        # 암호화 체크박스와 암호 필드 연결
        self.p2p_encryption_checkbox.stateChanged.connect(self.toggle_encryption_fields)
        
    def toggle_encryption_fields(self, state):
        # 암호화 설정이 꺼져 있을 때 암호 필드 비활성화
        enabled = state == Qt.Checked
        self.sync_pass_edit.setEnabled(enabled)
        if not enabled:
            self.sync_pass_edit.clear()
    
    def load_settings_values(self):
        default_notes_dir = os.path.join(QStandardPaths.writableLocation(QStandardPaths.AppDataLocation), SETTINGS_APP, "Notes")
        self.notes_dir_edit.setText(self.settings.value("notesDirectory", defaultValue=default_notes_dir))
        
        self.p2p_enabled_checkbox.setChecked(self.settings.value("p2p/enabled", defaultValue=False, type=bool))
        self.p2p_encryption_checkbox.setChecked(self.settings.value("p2p/encryption", defaultValue=True, type=bool))
        self.sync_user_edit.setText(self.settings.value("p2p/username", defaultValue=""))
        self.sync_pass_edit.setText(self.settings.value("p2p/password", defaultValue=""))
        self.p2p_port_edit.setText(str(self.settings.value("p2p/listenPort", defaultValue=DEFAULT_P2P_PORT)))
        
        # 암호화 설정에 따라 암호 필드 활성화/비활성화
        self.toggle_encryption_fields(Qt.Checked if self.p2p_encryption_checkbox.isChecked() else Qt.Unchecked)
        
        self.peer_list_widget.clear()
        peers_json = self.settings.value("p2p/peers", defaultValue="[]")
        try:
            peers_data = json.loads(peers_json)
            for peer_data in peers_data:
                if isinstance(peer_data, dict) and "address" in peer_data and "port" in peer_data:
                    addr = peer_data["address"]
                    prt = peer_data["port"]
                    self.peer_list_widget.addItem(f"{addr}:{prt}")
        except json.JSONDecodeError:
            logging.error("Error loading peer list from settings.")
        
        self.webui_endpoint_edit.setText(self.settings.value("webui/endpoint", defaultValue=""))
        self.webui_apikey_edit.setText(self.settings.value("webui/apikey", defaultValue=""))
        # 프록시 설정 로드
        self.disable_proxy_checkbox.setChecked(self.settings.value("webui/disable_proxy", defaultValue=False, type=bool))
    
    
        # Google API 설정 로드
        self.google_api_key_edit.setText(self.settings.value("google/apikey", defaultValue=""))
        self.google_cx_edit.setText(self.settings.value("google/cx", defaultValue=""))
        
        saved_models = self.settings.value("webui/available_models", defaultValue=[])
        selected_model = self.settings.value("webui/selected_model", defaultValue="")
        
        self.webui_model_combo.clear()
        if saved_models:
            if saved_models and isinstance(saved_models[0], dict):
                model_names = [m.get("name", m.get("id", "")) for m in saved_models]
            else:
                model_names = saved_models
            self.webui_model_combo.addItems(model_names)
            if selected_model in model_names:
                self.webui_model_combo.setCurrentText(selected_model)
        elif self.webui_endpoint_edit.text():
             QTimer.singleShot(100, self.fetch_webui_models)

    def browse_notes_directory(self):
        current_dir = self.notes_dir_edit.text()
        new_dir = QFileDialog.getExistingDirectory(self, "Select Notes Directory", current_dir)
        if new_dir and new_dir != current_dir:
            self.notes_dir_edit.setText(new_dir)

    def add_peer(self):
        text, ok = QInputDialog.getText(self, "Add Peer", "Enter Peer Address (IP:Port):")
        if ok and text:
            parts = text.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                self.peer_list_widget.addItem(text)
            else:
                QMessageBox.warning(self, "Invalid Format", "Please enter in IP:Port format (e.g., 192.168.1.100:61101).")

    def remove_peer(self):
        selected_items = self.peer_list_widget.selectedItems()
        if selected_items:
            for item in selected_items:
                self.peer_list_widget.takeItem(self.peer_list_widget.row(item))

    def fetch_webui_models(self):
        endpoint = self.webui_endpoint_edit.text().strip()
        api_key = self.webui_apikey_edit.text().strip()
        
        if not endpoint:
            QMessageBox.warning(self, "Missing Endpoint", "Please enter the Open WebUI Endpoint URL.")
            return
        
        models = []
        if not endpoint.endswith("/"):
            endpoint += "/"
        
        url = endpoint + "api/models"
        headers = {"Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        # 프록시 설정 가져오기
        proxy_disabled = self.disable_proxy_checkbox.isChecked()     
        try:
            logging.info(f"Fetching models from {url}")
            if not proxy_disabled:
                response = requests.get(url, headers=headers, timeout=10, verify=False, proxies={"http": Proxy_http, "https": Proxy_https})
            else:
                response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            res_text = response.content.decode("utf-8")
            result = json.loads(res_text)
            
            logging.info(f"OpenWebUI response structure: {list(result.keys()) if isinstance(result, dict) else 'Response is not a dictionary'}")
            
            if isinstance(result, list):
                for model in result:
                    if isinstance(model, dict) and "id" in model:
                        models.append({"id": model.get("id", ""), "name": model.get("name", model.get("id", ""))})
                    elif isinstance(model, str):
                        models.append({"id": model, "name": model})
            elif isinstance(result, dict):
                if "data" in result and isinstance(result["data"], list):
                    for model in result["data"]:
                        if isinstance(model, dict):
                            models.append({"id": model.get("id", ""), "name": model.get("name", model.get("id", ""))})
                        elif isinstance(model, str):
                            models.append({"id": model, "name": model})
                elif "models" in result and isinstance(result["models"], list):
                    for model in result["models"]:
                        if isinstance(model, dict):
                            models.append({"id": model.get("id", model.get("name", "")), "name": model.get("name", model.get("id", ""))})
                        elif isinstance(model, str):
                            models.append({"id": model, "name": model})
            
            if models:
                logging.info(f"Found models: {models}")
                current_selection = self.webui_model_combo.currentText()
                self.webui_model_combo.clear()
                model_name_list = [m["name"] for m in models]
                self.webui_model_combo.addItems(model_name_list)
                
                if current_selection in model_name_list:
                    self.webui_model_combo.setCurrentText(current_selection)
                elif model_name_list:
                    self.webui_model_combo.setCurrentIndex(0)
                
                QMessageBox.information(self, "Success", f"Successfully fetched {len(models)} models.")
                self.settings.setValue("webui/available_models", models)
            else:
                logging.warning("No models found in API response.")
                self.webui_model_combo.clear()
                QMessageBox.warning(self, "No Models", "No models found at the specified endpoint.")
                self.settings.setValue("webui/available_models", [])
                
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching models from {url}: {e}")
            QMessageBox.critical(self, "Fetch Error", f"Failed to fetch models:\n{e}")
            self.webui_model_combo.clear()
            self.settings.setValue("webui/available_models", [])
        except json.JSONDecodeError:
            logging.error(f"Error decoding JSON response from {url}")
            QMessageBox.critical(self, "Fetch Error", "Received invalid response from the server.")
            self.webui_model_combo.clear()
            self.settings.setValue("webui/available_models", [])
        except Exception as e:
            logging.error(f"Unexpected error fetching models: {e}", exc_info=True)
            QMessageBox.critical(self, "Fetch Error", f"An unexpected error occurred: {e}")
            self.webui_model_combo.clear()
            self.settings.setValue("webui/available_models", [])

    def save_and_close(self):
        self.settings.setValue("notesDirectory", self.notes_dir_edit.text())
        self.settings.setValue("p2p/enabled", self.p2p_enabled_checkbox.isChecked())
        self.settings.setValue("p2p/encryption", self.p2p_encryption_checkbox.isChecked())
        self.settings.setValue("p2p/username", self.sync_user_edit.text())
        
        # 암호화가 활성화된 경우에만 비밀번호 저장
        if self.p2p_encryption_checkbox.isChecked():
            self.settings.setValue("p2p/password", self.sync_pass_edit.text())
        else:
            self.settings.setValue("p2p/password", "")
        
        try:
            port = int(self.p2p_port_edit.text() or DEFAULT_P2P_PORT)
            if not (1024 <= port <= 65535):
                raise ValueError("Port out of range")
            self.settings.setValue("p2p/listenPort", port)
        except ValueError:
             QMessageBox.warning(self, "Invalid Port", f"Please enter a valid port number between 1024 and 65535. Using default {DEFAULT_P2P_PORT}.")
             self.settings.setValue("p2p/listenPort", DEFAULT_P2P_PORT)
        
        peers_data = []
        for i in range(self.peer_list_widget.count()):
            item_text = self.peer_list_widget.item(i).text()
            parts = item_text.split(":")
            if len(parts) == 2:
                peers_data.append({"address": parts[0], "port": int(parts[1])})
        
        self.settings.setValue("p2p/peers", json.dumps(peers_data))
        self.settings.setValue("webui/endpoint", self.webui_endpoint_edit.text().strip())
        self.settings.setValue("webui/apikey", self.webui_apikey_edit.text().strip())
        self.settings.setValue("webui/selected_model", self.webui_model_combo.currentText())
        # 프록시 설정 저장
        self.settings.setValue("webui/disable_proxy", self.disable_proxy_checkbox.isChecked())
        # Google API 설정 저장
        self.settings.setValue("google/apikey", self.google_api_key_edit.text().strip())
        self.settings.setValue("google/cx", self.google_cx_edit.text().strip())
        
        self.settings_updated_signal.emit()
        self.accept()

# --- Clipboard Item Class ---
class ClipboardItem:
    def __init__(self, data_type, data, timestamp=None):
        self.data_type = data_type
        self.data = data
        self.timestamp = timestamp or time.time()

    def to_dict(self):
        data_dict = {"type": self.data_type, "timestamp": self.timestamp}
        if self.data_type == "text":
            data_dict["content"] = self.data
        elif self.data_type == "image" and isinstance(self.data, QPixmap):
            try:
                buffer = QBuffer()
                buffer.open(QIODevice.WriteOnly)
                self.data.save(buffer, "PNG")
                img_data = buffer.data()
                data_dict["content"] = base64.b64encode(img_data).decode("utf-8")
            except Exception as e:
                logging.error(f"Error encoding image to dict: {e}")
                return None
        else:
            return None
        return data_dict

    @classmethod
    def from_dict(cls, data_dict):
        data_type = data_dict.get("type")
        content = data_dict.get("content")
        timestamp = data_dict.get("timestamp", time.time())
        
        if data_type == "text":
            return cls("text", content, timestamp)
        elif data_type == "image" and content:
            try:
                img_data = base64.b64decode(content)
                pixmap = QPixmap()
                if pixmap.loadFromData(img_data):
                    return cls("image", pixmap, timestamp)
                else:
                    logging.warning("Failed to load image data from dict")
            except Exception as e:
                logging.error(f"Error decoding image from dict: {e}")
        
        return None

# --- P2P Manager (Modified for encryption option) ---
class P2PManager(QObject):
    peer_status_changed = Signal(str, int, str)
    received_data = Signal(dict)
    log_message = Signal(str)

    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.peers = {}
        self.listen_socket = None
        self.listen_port = DEFAULT_P2P_PORT
        self.running = False
        self.encryption_key = None
        self.username = ""
        self.password = ""
        self.p2p_enabled = False
        # 암호화 설정 추가
        self.encryption_enabled = True
        self.load_config()

    def load_config(self):
        try:
            self.p2p_enabled = self.settings.value("p2p/enabled", defaultValue=False, type=bool)
            # 암호화 설정 로드
            self.encryption_enabled = self.settings.value("p2p/encryption", defaultValue=True, type=bool)
            self.username = self.settings.value("p2p/username", "")
            self.password = self.settings.value("p2p/password", "")
            self.listen_port = int(self.settings.value("p2p/listenPort", DEFAULT_P2P_PORT))
            
            # 암호화가 활성화된 경우에만 키 유도
            if self.encryption_enabled:
                self.derive_key()
            else:
                self.encryption_key = None
                logging.info("P2P encryption disabled in settings.")
            
            self.peers.clear()
            peers_json = self.settings.value("p2p/peers", "[]")
            peers_data = json.loads(peers_json)
            
            for peer_data in peers_data:
                peer = Peer.from_dict(peer_data)
                self.peers[f"{peer.address}:{peer.port}"] = peer
            
            logging.info("P2P config loaded.")
        except Exception as e:
            logging.error(f"Error loading P2P config: {e}")
            self.p2p_enabled = False

    def derive_key(self):
        if not self.password:
            self.encryption_key = None
            logging.warning("P2P password not set, encryption key cannot be derived.")
            return
        
        try:
            salt_hex = self.settings.value("p2p/salt")
            if salt_hex:
                salt = bytes.fromhex(salt_hex)
            else:
                # 솔트가 없으면 키를 유도할 수 없음
                logging.warning("P2P salt not yet set. Key will be derived after salt exchange.")
                self.encryption_key = None
                return
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(), 
                length=AES_KEY_SIZE, 
                salt=salt,
                iterations=PBKDF2_ITERATIONS, 
                backend=default_backend()
            )
            
            self.encryption_key = kdf.derive(self.password.encode("utf-8"))
            logging.info("P2P encryption key derived successfully.")
            
        except Exception as e:
            self.encryption_key = None
            logging.error(f"Error deriving P2P encryption key: {e}")

    def encrypt_data(self, data):
        if not self.encryption_enabled:
            # 암호화가 비활성화된 경우, JSON 직렬화만 수행
            try:
                json_data = json.dumps(data).encode("utf-8")
                return json_data
            except Exception as e:
                logging.error(f"P2P data serialization failed: {e}")
                return None
        
        if not self.encryption_key:
            logging.warning("Encryption key not available, cannot encrypt P2P data.")
            return None
        
        try:
            aesgcm = AESGCM(self.encryption_key)
            nonce = os.urandom(NONCE_SIZE)
            json_data = json.dumps(data).encode("utf-8")
            encrypted_data = aesgcm.encrypt(nonce, json_data, None)
            return nonce + encrypted_data
        except Exception as e:
            logging.error(f"P2P data encryption failed: {e}")
            return None

    def decrypt_data(self, encrypted_payload):
        if not self.encryption_enabled:
            # 암호화가 비활성화된 경우, JSON 역직렬화만 수행
            try:
                return json.loads(encrypted_payload.decode("utf-8"))
            except Exception as e:
                logging.warning(f"P2P data deserialization failed: {e}")
                return None
        
        if not self.encryption_key:
            logging.warning("Encryption key not available, cannot decrypt P2P data.")
            return None
        
        if len(encrypted_payload) < NONCE_SIZE + TAG_SIZE:
            logging.warning("Encrypted payload too short for P2P decryption.")
            return None
        
        try:
            nonce = encrypted_payload[:NONCE_SIZE]
            encrypted_data = encrypted_payload[NONCE_SIZE:]
            aesgcm = AESGCM(self.encryption_key)
            decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
            return json.loads(decrypted_data.decode("utf-8"))
        except Exception as e:
            logging.warning(f"P2P data decryption failed: {e}")
            return None

    @Slot()
    def start(self):
        if self.running:
            return
        
        self.load_config()
        
        if not self.p2p_enabled:
            logging.info("P2P sync is disabled in settings.")
            self.log_message.emit("P2P Disabled")
            return
        
        # 암호화가 활성화된 경우 사용자 이름과 비밀번호 확인
        if self.encryption_enabled and (not self.username or not self.password):
            logging.warning("P2P sync cannot start: Username or password missing with encryption enabled.")
            self.log_message.emit("P2P Creds Missing")
            self.p2p_enabled = False
            return
        
        # 암호화가 비활성화된 경우 사용자 이름만 확인
        if not self.encryption_enabled and not self.username:
            logging.warning("P2P sync cannot start: Username missing.")
            self.log_message.emit("P2P Username Missing")
            self.p2p_enabled = False
            return
        
        if not self.peers:
            logging.warning("P2P sync cannot start: No peers configured.")
            self.log_message.emit("P2P No Peers")
            self.p2p_enabled = False
            return
        
        self.running = True
        logging.info(f"Starting P2P Manager on port {self.listen_port}... (Encryption: {'Enabled' if self.encryption_enabled else 'Disabled'})")
        self.log_message.emit(f"P2P Starting (Port: {self.listen_port})")
        
        listen_thread = threading.Thread(target=self._listen_for_peers, daemon=True, name="P2PListenThread")
        listen_thread.start()
        
        connect_thread = threading.Thread(target=self._connect_to_peers, daemon=True, name="P2PConnectThread")
        connect_thread.start()

    @Slot()
    def stop(self):
        if not self.running:
            return
        
        self.running = False
        logging.info("Stopping P2P Manager...")
        
        if self.listen_socket:
            try:
                self.listen_socket.close()
            except Exception as e:
                logging.error(f"Error closing listen socket: {e}")
            self.listen_socket = None
        
        active_connections = []
        for peer_key, peer in list(self.peers.items()):
            if peer.connection:
                active_connections.append(peer.connection)
                peer.connection = None
            peer.status = "Disconnected"
            peer.authenticated = False
            try:
                self.peer_status_changed.emit(peer.address, peer.port, peer.status)
            except RuntimeError:
                pass
        
        time.sleep(0.2)
        
        for conn in active_connections:
             try:
                 conn.shutdown(socket.SHUT_RDWR)
                 conn.close()
             except Exception as e:
                 logging.debug(f"Error force closing peer connection: {e}")
        
        logging.info("P2P Manager stopped.")
        self.log_message.emit("P2P Stopped")

    def _listen_for_peers(self):
        try:
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listen_socket.bind(("0.0.0.0", self.listen_port))
            self.listen_socket.listen(5)
            logging.info(f"P2P Listener: Listening on 0.0.0.0:{self.listen_port}")
        except Exception as e:
            logging.error(f"Error starting P2P listener: {e}")
            self.log_message.emit(f"P2P Listen Error: {e}")
            self.running = False
            return
        
        while self.running:
            try:
                conn, addr = self.listen_socket.accept()
                logging.info(f"P2P Listener: Incoming connection from {addr[0]}:{addr[1]}")
                handler_thread = threading.Thread(
                    target=self._handle_peer_connection, 
                    args=(conn, addr), 
                    daemon=True, 
                    name=f"P2PHandlerIn-{addr[0]}"
                )
                handler_thread.start()
            except OSError:
                if self.running:
                    logging.warning("P2P Listener: Socket closed or error.")
                break
            except Exception as e:
                if self.running:
                    logging.error(f"P2P Listener: Accept error: {e}")
                time.sleep(1)
        
        if self.listen_socket:
            try:
                self.listen_socket.close()
            except:
                pass
        
        logging.info("P2P Listener thread stopped.")

    def _connect_to_peers(self):
        while self.running:
            connected_peers_count = 0
            
            for peer_key, peer in list(self.peers.items()):
                if not self.running:
                    break
                
                if not peer.connection:
                    try:
                        self.peer_status_changed.emit(peer.address, peer.port, "Connecting...")
                        conn_attempt = socket.create_connection((peer.address, peer.port), timeout=10)
                        peer.connection = conn_attempt 
                        peer.status = "Connected (Handshaking...)"
                        self.peer_status_changed.emit(peer.address, peer.port, peer.status)
                        logging.info(f"P2P Connector: Connected to {peer.address}:{peer.port}")
                        
                        handler_thread = threading.Thread(
                            target=self._handle_peer_connection, 
                            args=(conn_attempt, (peer.address, peer.port)), 
                            daemon=True, 
                            name=f"P2PHandlerOut-{peer.address}"
                        )
                        handler_thread.start()
                        connected_peers_count += 1
                    except socket.timeout:
                        peer.status = "Timeout"
                        self.peer_status_changed.emit(peer.address, peer.port, peer.status)
                        if peer.connection:
                            peer.connection = None
                    except ConnectionRefusedError:
                        peer.status = "Refused"
                        self.peer_status_changed.emit(peer.address, peer.port, peer.status)
                        if peer.connection:
                            peer.connection = None
                    except Exception as e:
                        logging.warning(f"P2P Connector: Failed to connect to {peer.address}:{peer.port}: {e}")
                        peer.status = "Error"
                        self.peer_status_changed.emit(peer.address, peer.port, peer.status)
                        if peer.connection:
                            peer.connection = None
                else:
                    connected_peers_count += 1
            
            if connected_peers_count == 0 and self.peers:
                 self.log_message.emit("P2P No Peers Connected")
            
            for _ in range(300):
                 if not self.running:
                     break
                 time.sleep(0.1)
        
        logging.info("P2P Connector thread stopped.")

    def _exchange_salt_and_ready(self, conn, peer_address_tuple):
        peer_addr_str = f"{peer_address_tuple[0]}:{peer_address_tuple[1]}"
        logging.info(f"[{peer_addr_str}] Starting salt exchange and ready protocol.")
        
        # 암호화가 비활성화된 경우, 솔트 교환 없이 진행
        if not self.encryption_enabled:
            logging.info(f"[{peer_addr_str}] Encryption disabled, skipping salt exchange.")
            return self._exchange_encryption_setting(conn, peer_address_tuple)
        
        # 로컬 솔트 확인 또는 생성
        my_current_salt_hex = self.settings.value("p2p/salt")
        if not my_current_salt_hex:
            new_salt_bytes = os.urandom(SALT_SIZE)
            my_current_salt_hex = new_salt_bytes.hex()
            self.settings.setValue("p2p/salt", my_current_salt_hex)
            logging.info(f"[{peer_addr_str}] No local salt found, generated new one: {my_current_salt_hex}")
            if self.password:
                self.derive_key()

        conn.settimeout(20)

        def _send_plain_json(sock, data_dict):
            payload = json.dumps(data_dict).encode("utf-8")
            sock.sendall(len(payload).to_bytes(4, "big") + payload)

        def _recv_plain_json(sock):
            len_bytes = sock.recv(4)
            if not len_bytes or len(len_bytes) < 4:
                logging.warning(f"[{peer_addr_str}] SaltEx: Failed to receive length bytes.")
                return None
            
            msg_len = int.from_bytes(len_bytes, "big")
            if msg_len <= 0 or msg_len > 1 * 1024 * 1024:
                logging.error(f"[{peer_addr_str}] SaltEx: Handshake message too large or invalid: {msg_len} bytes")
                return None
            
            buffer = b""
            while len(buffer) < msg_len:
                chunk = sock.recv(min(msg_len - len(buffer), 4096))
                if not chunk:
                    logging.warning(f"[{peer_addr_str}] SaltEx: Connection closed while receiving message body.")
                    return None
                buffer += chunk
            
            return json.loads(buffer.decode("utf-8"))

        # 통신 시작
        is_initiator_role = False
        try:
            logging.debug(f"[{peer_addr_str}] SaltEx: Attempting to receive AUTH_SALT_EXCHANGE (acting as responder).")
            conn.settimeout(5)
            msg = _recv_plain_json(conn)
            conn.settimeout(20)

            if msg and msg.get("type") == "AUTH_SALT_EXCHANGE":
                logging.info(f"[{peer_addr_str}] SaltEx: Received AUTH_SALT_EXCHANGE (Responder Path).")
                peer_salt_hex = msg.get("salt")
                
                if not peer_salt_hex or not isinstance(peer_salt_hex, str) or len(bytes.fromhex(peer_salt_hex)) != SALT_SIZE:
                    logging.warning(f"[{peer_addr_str}] SaltEx: Invalid peer salt received: {peer_salt_hex}")
                    return False

                # 솔트 비교 및 선택
                my_salt_for_cmp = self.settings.value("p2p/salt")
                if peer_salt_hex < my_salt_for_cmp:
                    logging.info(f"[{peer_addr_str}] SaltEx: Adopting peer's smaller salt: {peer_salt_hex}. My old: {my_salt_for_cmp}")
                    self.settings.setValue("p2p/salt", peer_salt_hex)
                    if self.password:
                        self.derive_key()
                elif my_salt_for_cmp < peer_salt_hex:
                    logging.info(f"[{peer_addr_str}] SaltEx: My salt {my_salt_for_cmp} is smaller. Peer should adopt.")
                else:
                    logging.info(f"[{peer_addr_str}] SaltEx: Salts already match: {my_salt_for_cmp}")
                
                # ACK 전송
                _send_plain_json(conn, {"type": "AUTH_SALT_EXCHANGE_ACK", "salt": self.settings.value("p2p/salt")})
                logging.info(f"[{peer_addr_str}] SaltEx: Sent AUTH_SALT_EXCHANGE_ACK.")

                # DONE 및 READY 교환
                resp_done = _recv_plain_json(conn)
                if not resp_done or resp_done.get("type") != "AUTH_SALT_DONE":
                    return False
                
                _send_plain_json(conn, {"type": "AUTH_SALT_DONE"})
                
                resp_ready = _recv_plain_json(conn)
                if not resp_ready or resp_ready.get("type") != "AUTH_READY":
                    return False
                
                _send_plain_json(conn, {"type": "AUTH_READY"})
                logging.info(f"[{peer_addr_str}] SaltEx: Responder path successful.")
                
                # 암호화 설정 교환
                return self._exchange_encryption_setting(conn, peer_address_tuple)
            else:
                is_initiator_role = True
                if msg:
                    logging.debug(f"[{peer_addr_str}] SaltEx: Did not receive salt exchange, or wrong type ({msg.get('type')}). Will initiate.")
        
        except socket.timeout:
            is_initiator_role = True
            logging.debug(f"[{peer_addr_str}] SaltEx: Timeout receiving initial salt msg, initiating.")
        except (ConnectionResetError, BrokenPipeError, json.JSONDecodeError, ValueError, TypeError) as e:
            logging.error(f"[{peer_addr_str}] SaltEx: Error in responder pre-initiation: {e}")
            return False
        except Exception as e:
            logging.error(f"[{peer_addr_str}] SaltEx: Generic error in responder pre-initiation: {e}", exc_info=True)
            return False
        finally:
            conn.settimeout(20)

        if is_initiator_role:
            try:
                logging.info(f"[{peer_addr_str}] SaltEx: Initiating salt exchange (Initiator Path).")
                my_salt_to_send = self.settings.value("p2p/salt")
                _send_plain_json(conn, {"type": "AUTH_SALT_EXCHANGE", "salt": my_salt_to_send })
                logging.info(f"[{peer_addr_str}] SaltEx: Sent AUTH_SALT_EXCHANGE with salt {my_salt_to_send}.")

                resp_ack = _recv_plain_json(conn)
                if not resp_ack or resp_ack.get("type") != "AUTH_SALT_EXCHANGE_ACK":
                    return False
                
                peer_acked_salt_hex = resp_ack.get("salt")
                if not peer_acked_salt_hex or not isinstance(peer_acked_salt_hex, str) or len(bytes.fromhex(peer_acked_salt_hex)) != SALT_SIZE:
                    logging.warning(f"[{peer_addr_str}] SaltEx: Invalid salt in ACK: {peer_acked_salt_hex}")
                    return False

                if peer_acked_salt_hex != self.settings.value("p2p/salt"):
                    self.settings.setValue("p2p/salt", peer_acked_salt_hex)
                    logging.info(f"[{peer_addr_str}] SaltEx: Adopted salt {peer_acked_salt_hex} from peer ACK.")
                    if self.password:
                        self.derive_key()
                elif peer_acked_salt_hex == self.settings.value("p2p/salt"):
                    logging.info(f"[{peer_addr_str}] SaltEx: Salts confirmed match after ACK: {peer_acked_salt_hex}")
                else:
                    logging.warning(f"[{peer_addr_str}] SaltEx: Salt mismatch after ACK. My salt: {self.settings.value('p2p/salt')}, Peer ACKed: {peer_acked_salt_hex}. This is unexpected.")
                    self.settings.setValue("p2p/salt", peer_acked_salt_hex)
                    if self.password:
                        self.derive_key()

                # DONE 및 READY 교환
                _send_plain_json(conn, {"type": "AUTH_SALT_DONE"})
                
                resp_done = _recv_plain_json(conn)
                if not resp_done or resp_done.get("type") != "AUTH_SALT_DONE":
                    return False
                
                _send_plain_json(conn, {"type": "AUTH_READY"})
                
                resp_ready = _recv_plain_json(conn)
                if not resp_ready or resp_ready.get("type") != "AUTH_READY":
                    return False
                
                logging.info(f"[{peer_addr_str}] SaltEx: Initiator path successful.")
                
                # 암호화 설정 교환
                return self._exchange_encryption_setting(conn, peer_address_tuple)
            except (socket.timeout, ConnectionResetError, BrokenPipeError, json.JSONDecodeError, ValueError, TypeError) as e:
                logging.error(f"[{peer_addr_str}] SaltEx: Error in initiator path: {e}")
                return False
            except Exception as e:
                logging.error(f"[{peer_addr_str}] SaltEx: Generic error in initiator path: {e}", exc_info=True)
                return False
        
        logging.error(f"[{peer_addr_str}] SaltEx: Logic error, unexpected end of function.")
        return False

    # 암호화 설정 교환 추가
    def _exchange_encryption_setting(self, conn, peer_address_tuple):
        peer_addr_str = f"{peer_address_tuple[0]}:{peer_address_tuple[1]}"
        logging.info(f"[{peer_addr_str}] Starting encryption setting exchange.")
        
        conn.settimeout(10)
        
        def _send_plain_json(sock, data_dict):
            payload = json.dumps(data_dict).encode("utf-8")
            sock.sendall(len(payload).to_bytes(4, "big") + payload)

        def _recv_plain_json(sock):
            len_bytes = sock.recv(4)
            if not len_bytes or len(len_bytes) < 4:
                return None
            
            msg_len = int.from_bytes(len_bytes, "big")
            if msg_len <= 0 or msg_len > 1 * 1024 * 1024:
                return None
            
            buffer = b""
            while len(buffer) < msg_len:
                chunk = sock.recv(min(msg_len - len(buffer), 4096))
                if not chunk:
                    return None
                buffer += chunk
            
            return json.loads(buffer.decode("utf-8"))
        
        try:
            # 암호화 설정 전송
            _send_plain_json(conn, {
                "type": "ENCRYPTION_CONFIG",
                "encryption_enabled": self.encryption_enabled
            })
            
            # 상대방의 암호화 설정 수신
            peer_config = _recv_plain_json(conn)
            if not peer_config or peer_config.get("type") != "ENCRYPTION_CONFIG":
                logging.error(f"[{peer_addr_str}] Invalid encryption config response from peer.")
                return False
            
            peer_encryption_enabled = peer_config.get("encryption_enabled", True)
            
            # 설정이 일치하는지 확인
            if self.encryption_enabled != peer_encryption_enabled:
                logging.error(f"[{peer_addr_str}] Encryption setting mismatch: Local={self.encryption_enabled}, Peer={peer_encryption_enabled}")
                _send_plain_json(conn, {"type": "ENCRYPTION_CONFIG_RESULT", "result": "mismatch"})
                return False
            
            # 결과 확인 교환
            _send_plain_json(conn, {"type": "ENCRYPTION_CONFIG_RESULT", "result": "match"})
            
            peer_result = _recv_plain_json(conn)
            if not peer_result or peer_result.get("type") != "ENCRYPTION_CONFIG_RESULT" or peer_result.get("result") != "match":
                logging.error(f"[{peer_addr_str}] Encryption config result mismatch or invalid.")
                return False
            
            logging.info(f"[{peer_addr_str}] Encryption setting exchange successful: {self.encryption_enabled}")
            return True
            
        except Exception as e:
            logging.error(f"[{peer_addr_str}] Error in encryption setting exchange: {e}")
            return False
        finally:
            conn.settimeout(20)  # 원래 타임아웃으로 복원

    def _handle_peer_connection(self, conn, addr):
        peer_key = f"{addr[0]}:{addr[1]}"
        peer_obj_for_handler = self.peers.get(peer_key)
        is_known_peer = bool(peer_obj_for_handler)

        if not is_known_peer:
            temp_peer_obj = Peer(addr[0], addr[1], "Handshaking...")
            logging.info(f"P2P Handler: Handling new incoming connection from unknown address {peer_key}")
        else:
            peer_obj_for_handler.connection = conn
            peer_obj_for_handler.status = "Handshaking..."
            try:
                self.peer_status_changed.emit(peer_obj_for_handler.address, peer_obj_for_handler.port, peer_obj_for_handler.status)
            except RuntimeError:
                pass

        current_peer_object = peer_obj_for_handler if is_known_peer else temp_peer_obj

        salt_exchange_successful = False
        try:
            salt_exchange_successful = self._exchange_salt_and_ready(conn, addr)
        except Exception as salt_err:
            logging.error(f"[{peer_key}] P2P Handler: Exception during salt exchange: {salt_err}", exc_info=True)
            salt_exchange_successful = False

        if not salt_exchange_successful:
            logging.warning(f"[{peer_key}] P2P Handler: Salt/encryption exchange failed. Closing connection.")
            if is_known_peer and self.peers.get(peer_key):
                 self.peers[peer_key].status = "Salt Fail"
                 if self.peers[peer_key].connection == conn:
                     self.peers[peer_key].connection = None
                 try:
                     self.peer_status_changed.emit(current_peer_object.address, current_peer_object.port, "Salt Fail")
                 except RuntimeError:
                     pass
            try:
                conn.close()
            except:
                pass
            return
        
        logging.info(f"[{peer_key}] P2P Handler: Salt exchange successful. Proceeding to authentication.")
        current_peer_object.status = "Authenticating..."
        if is_known_peer:
            try:
                self.peer_status_changed.emit(current_peer_object.address, current_peer_object.port, current_peer_object.status)
            except RuntimeError:
                pass

        authenticated = False
        try:
            authenticated = self._perform_authentication(conn, current_peer_object) 
        except Exception as auth_err:
             logging.error(f"[{peer_key}] P2P Handler: Exception during _perform_authentication: {auth_err}", exc_info=True)
             authenticated = False
        
        if not authenticated:
            logging.warning(f"[{peer_key}] P2P Handler: Authentication failed. Closing connection.")
            current_peer_object.status = "Auth Fail"
            current_peer_object.authenticated = False
            if is_known_peer and self.peers.get(peer_key):
                 if self.peers[peer_key].connection == conn:
                     self.peers[peer_key].connection = None
                 try:
                     self.peer_status_changed.emit(current_peer_object.address, current_peer_object.port, "Auth Fail")
                 except RuntimeError:
                     pass
            try:
                conn.close()
            except:
                pass
            return

        logging.info(f"[{peer_key}] P2P Handler: Full authentication successful.")
        current_peer_object.authenticated = True
        current_peer_object.status = "Connected"
        if is_known_peer:
            try:
                self.peer_status_changed.emit(current_peer_object.address, current_peer_object.port, "Connected")
            except RuntimeError:
                pass
        else:
            logging.info(f"P2P Handler: Authenticated incoming unknown peer: {peer_key}. Will handle data but not add to permanent peer list.")

        buffer = b""
        msg_len = -1
        active_conn_for_loop = conn 
        while self.running and active_conn_for_loop and current_peer_object.authenticated:
            try:
                data = active_conn_for_loop.recv(8192)
                if not data:
                    logging.info(f"P2P Handler: Peer {peer_key} disconnected gracefully.")
                    break
                
                buffer += data
                while self.running:
                    if msg_len == -1:
                        if len(buffer) >= 4:
                            msg_len = int.from_bytes(buffer[:4], "big")
                            buffer = buffer[4:]
                        else:
                            break
                    
                    if msg_len != -1:
                        if len(buffer) >= msg_len:
                            encrypted_msg_payload = buffer[:msg_len]
                            buffer = buffer[msg_len:]
                            msg_len = -1
                            
                            # 메시지 복호화
                            decrypted_msg = self.decrypt_data(encrypted_msg_payload)
                            if decrypted_msg:
                                logging.info(f"P2P Handler: Received from {peer_key}: type {decrypted_msg.get('type')}")
                                try:
                                    if self.received_data is not None:
                                         QMetaObject.invokeMethod(self, "emit_received_data_signal", Qt.QueuedConnection, Q_ARG(dict, decrypted_msg))
                                except RuntimeError as e:
                                    logging.warning(f"P2P Handler: RuntimeError emitting received_data for {peer_key}: {e}")
                            else:
                                 logging.warning(f"P2P Handler: Failed to decrypt message from {peer_key}. Ignoring.")
                        else:
                            break
            except socket.timeout:
                logging.debug(f"P2P Handler: Socket timeout for {peer_key}, continuing.")
                continue
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                logging.warning(f"P2P Handler: Connection error with {peer_key}: {e}")
                break
            except Exception as e:
                logging.error(f"P2P Handler: Error receiving data from {peer_key}: {e}", exc_info=True)
                break
        
        current_peer_object.authenticated = False
        current_peer_object.status = "Disconnected"
        if is_known_peer and self.peers.get(peer_key):
            if self.peers[peer_key].connection == conn:
                self.peers[peer_key].connection = None
            try: 
                if self.peer_status_changed is not None:
                    self.peer_status_changed.emit(current_peer_object.address, current_peer_object.port, "Disconnected")
            except RuntimeError:
                pass
        
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except (OSError, socket.error):
            pass
        try:
            conn.close()
        except (OSError, socket.error):
            pass
        
        logging.info(f"P2P Handler for {peer_key} finished.")

    @Slot(dict)
    def emit_received_data_signal(self, data):
        # 이 슬롯은 QMetaObject.invokeMethod를 통해 P2PManager의 스레드 컨텍스트에서 시그널을 발생시킴
        self.received_data.emit(data)

    def _perform_authentication(self, conn, peer_obj):
        peer_addr_str = f"{peer_obj.address}:{peer_obj.port}"
        
        # 암호화가 비활성화된 경우, 사용자 이름만 확인
        if not self.encryption_enabled:
            if not self.username:
                logging.warning(f"[{peer_addr_str}] Auth: Username not set locally.")
                return False
            
            try:
                conn.settimeout(15)
                
                # 사용자 이름만 교환
                auth_init_payload = {"type": "AUTH_INIT_SIMPLE", "username": self.username}
                conn.sendall(json.dumps(auth_init_payload).encode("utf-8"))
                logging.info(f"[{peer_addr_str}] Auth: Sent AUTH_INIT_SIMPLE (unencrypted).")
                
                # 상대방의 사용자 이름 수신
                data = b""
                while len(data) < 4096:  # 적절한 제한 설정
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    try:
                        peer_init = json.loads(data.decode("utf-8"))
                        if peer_init.get("type") == "AUTH_INIT_SIMPLE" and peer_init.get("username") == self.username:
                            logging.info(f"[{peer_addr_str}] Unencrypted authentication successful.")
                            conn.settimeout(None)
                            return True
                    except json.JSONDecodeError:
                        continue
                
                logging.warning(f"[{peer_addr_str}] Unencrypted authentication failed.")
                return False
                
            except Exception as e:
                logging.error(f"[{peer_addr_str}] Error in unencrypted authentication: {e}")
                return False
        
        # 암호화가 활성화된 경우 기존 인증 로직 사용
        if not self.username or not self.password:
            logging.warning(f"[{peer_addr_str}] Auth: Username or password not set locally.")
            return False
        
        if not self.encryption_key:
            logging.warning(f"[{peer_addr_str}] Auth: Encryption key not (yet) derived. Attempting to derive now.")
            self.derive_key()
            if not self.encryption_key:
                logging.error(f"[{peer_addr_str}] Auth: Encryption key still not derived after attempt. Cannot proceed.")
                return False
        
        try:
            conn.settimeout(25)

            # Mutual Authentication (Challenge-Response)
            auth_init_payload = {"type": "AUTH_INIT", "username": self.username}
            encrypted_init = self.encrypt_data(auth_init_payload)
            if not encrypted_init:
                return False
            
            self._send_message(conn, encrypted_init)
            logging.info(f"[{peer_addr_str}] Auth: Sent AUTH_INIT.")

            encrypted_resp_init = self._receive_message(conn)
            if not encrypted_resp_init:
                return False
            
            decrypted_resp_init = self.decrypt_data(encrypted_resp_init)
            if not decrypted_resp_init or decrypted_resp_init.get("type") != "AUTH_INIT" or decrypted_resp_init.get("username") != self.username:
                logging.warning(f"[{peer_addr_str}] Auth: Invalid peer AUTH_INIT response: {decrypted_resp_init}")
                return False
            
            logging.info(f"[{peer_addr_str}] Auth: Validated peer's AUTH_INIT.")

            # Challenge 1
            challenge1 = os.urandom(32)
            challenge1_payload = {"type": "AUTH_CHALLENGE_1", "challenge": base64.b64encode(challenge1).decode()}
            encrypted_challenge1 = self.encrypt_data(challenge1_payload)
            if not encrypted_challenge1:
                return False
            
            self._send_message(conn, encrypted_challenge1)
            logging.info(f"[{peer_addr_str}] Auth: Sent AUTH_CHALLENGE_1.")

            # Response 1
            encrypted_resp_challenge1 = self._receive_message(conn)
            if not encrypted_resp_challenge1:
                return False
            
            decrypted_resp_challenge1 = self.decrypt_data(encrypted_resp_challenge1)
            if not decrypted_resp_challenge1 or decrypted_resp_challenge1.get("type") != "AUTH_RESPONSE_1":
                logging.warning(f"[{peer_addr_str}] Auth: Invalid AUTH_RESPONSE_1 type: {decrypted_resp_challenge1}")
                return False
            
            received_hmac1_b64 = decrypted_resp_challenge1.get("response")
            if not received_hmac1_b64:
                return False
            
            try:
                received_hmac1 = base64.b64decode(received_hmac1_b64)
            except Exception:
                return False
            
            expected_hmac1 = hmac.new(self.encryption_key, challenge1, hashlib.sha256).digest()
            if not hmac.compare_digest(expected_hmac1, received_hmac1):
                logging.warning(f"[{peer_addr_str}] Auth: HMAC_1 mismatch.")
                return False
            
            logging.info(f"[{peer_addr_str}] Auth: Validated AUTH_RESPONSE_1 from peer.")

            # Challenge 2
            encrypted_challenge2 = self._receive_message(conn)
            if not encrypted_challenge2:
                return False
            
            decrypted_challenge2 = self.decrypt_data(encrypted_challenge2)
            if not decrypted_challenge2 or decrypted_challenge2.get("type") != "AUTH_CHALLENGE_2":
                logging.warning(f"[{peer_addr_str}] Auth: Invalid AUTH_CHALLENGE_2 type: {decrypted_challenge2}")
                return False
            
            challenge2_b64 = decrypted_challenge2.get("challenge")
            if not challenge2_b64:
                return False
            
            try:
                challenge2_bytes = base64.b64decode(challenge2_b64)
            except Exception:
                return False
            
            logging.info(f"[{peer_addr_str}] Auth: Received AUTH_CHALLENGE_2 from peer.")

            # Response 2
            response2_hmac = hmac.new(self.encryption_key, challenge2_bytes, hashlib.sha256).digest()
            response2_payload = {"type": "AUTH_RESPONSE_2", "response": base64.b64encode(response2_hmac).decode()}
            encrypted_response2 = self.encrypt_data(response2_payload)
            if not encrypted_response2:
                return False
            
            self._send_message(conn, encrypted_response2)
            logging.info(f"[{peer_addr_str}] Auth: Sent AUTH_RESPONSE_2.")

            # Auth OK
            auth_ok_payload = {"type": "AUTH_OK"}
            encrypted_auth_ok = self.encrypt_data(auth_ok_payload)
            if not encrypted_auth_ok:
                return False
            
            self._send_message(conn, encrypted_auth_ok)
            logging.info(f"[{peer_addr_str}] Auth: Sent AUTH_OK.")

            # Peer Auth OK
            encrypted_peer_auth_ok = self._receive_message(conn)
            if not encrypted_peer_auth_ok:
                return False
            
            decrypted_peer_auth_ok = self.decrypt_data(encrypted_peer_auth_ok)
            if not decrypted_peer_auth_ok or decrypted_peer_auth_ok.get("type") != "AUTH_OK":
                logging.warning(f"[{peer_addr_str}] Auth: Invalid peer AUTH_OK: {decrypted_peer_auth_ok}")
                return False
            
            logging.info(f"Authentication successful with {peer_addr_str}")
            conn.settimeout(None)
            return True

        except socket.timeout:
            logging.warning(f"Authentication timed out with {peer_addr_str}")
            return False
        except (ConnectionResetError, BrokenPipeError) as e:
            logging.warning(f"Connection error during authentication with {peer_addr_str}: {e}")
            return False
        except Exception as e:
            logging.error(f"Generic authentication error with {peer_addr_str}: {e}", exc_info=True)
            return False

    def _send_message(self, conn, encrypted_payload):
        if conn is None:
            logging.error("P2P Send: Connection is None.")
            raise ConnectionAbortedError("Connection is None for send")
        
        try:
            msg_len_bytes = len(encrypted_payload).to_bytes(4, "big")
            conn.sendall(msg_len_bytes + encrypted_payload)
        except socket.error as e:
            logging.error(f"P2P Send: Socket error: {e}")
            raise
        except Exception as e:
            logging.error(f"P2P Send: Unexpected error: {e}")
            raise

    def _receive_message(self, conn):
        if conn is None:
            logging.error("P2P Receive: Connection is None.")
            return None
        
        try:
            len_bytes = conn.recv(4)
            if not len_bytes or len(len_bytes) < 4:
                logging.warning("P2P Receive: Failed to get length bytes or connection closed.")
                return None
            
            msg_len = int.from_bytes(len_bytes, "big")
            if msg_len <= 0 or msg_len > 10 * 1024 * 1024:
                logging.error(f"P2P Receive: Invalid message length: {msg_len}")
                return None 
            
            chunks = []
            bytes_recd = 0
            while bytes_recd < msg_len:
                if not self.running: 
                    logging.info("P2P Receive: Manager stopping, aborting receive.")
                    return None
                
                chunk = conn.recv(min(msg_len - bytes_recd, 8192))
                if not chunk:
                    logging.warning("P2P Receive: Connection closed by peer while receiving message body.")
                    return None
                
                chunks.append(chunk)
                bytes_recd += len(chunk)
            
            return b"".join(chunks)
        
        except socket.timeout:
            logging.debug("P2P Receive: Socket timeout.")
            return None
        except socket.error as e:
            logging.error(f"P2P Receive: Socket error: {e}")
            return None
        except Exception as e:
            logging.error(f"P2P Receive: Unexpected error: {e}")
            return None

    @Slot(dict)
    def send_to_all_peers(self, data_dict_to_send):
        if not self.running or not self.p2p_enabled:
            logging.debug("P2P SendAll: Not running or P2P disabled.")
            return
        
        if self.encryption_enabled and not self.encryption_key:
            logging.error("P2P SendAll: Encryption key not available but encryption is enabled. Cannot send.")
            return
        
        encrypted_payload = self.encrypt_data(data_dict_to_send)
        if not encrypted_payload:
            logging.error("P2P SendAll: Failed to encrypt data. Aborting send.")
            return

        sent_count = 0
        for peer_key, peer in list(self.peers.items()):
            if peer.connection and peer.authenticated:
                try:
                    logging.debug(f"P2P SendAll: Sending data (type: {data_dict_to_send.get('type')}) to {peer_key}")
                    self._send_message(peer.connection, encrypted_payload)
                    sent_count += 1
                except Exception as e:
                    logging.warning(f"P2P SendAll: Failed to send to {peer_key}: {e}. Marking disconnected.")
                    peer.status = "Send Error"
                    peer.authenticated = False
                    if peer.connection:
                        try:
                            peer.connection.close()
                        except:
                            pass
                        peer.connection = None
                    try: 
                        if self.peer_status_changed is not None:
                            self.peer_status_changed.emit(peer.address, peer.port, peer.status)
                    except RuntimeError:
                        pass
        
        if sent_count > 0:
            logging.info(f"P2P SendAll: Sent data (type: {data_dict_to_send.get('type')}) to {sent_count} authenticated peers.")
        elif self.peers:
            logging.info(f"P2P SendAll: Data (type: {data_dict_to_send.get('type')}) not sent (no authenticated peers currently available).")

# --- WebUI Worker ---
class WebUIWorker(QObject):
    finished = Signal()
    error = Signal(str)
    models_fetched = Signal(list)
    stream_chunk = Signal(str)
    stream_finished = Signal()

    def __init__(self, endpoint, api_key, model=None, messages=None, proxy_disabled=True):
        super().__init__()
        self.endpoint = endpoint
        self.api_key = api_key
        self.model = model
        self.messages = messages if messages else []
        self._running = True
        self.proxy_disabled = proxy_disabled  # 프록시 사용 여부 설정 추가

    @Slot()
    def run_fetch_models(self):
        if not self.endpoint:
            self.error.emit("Endpoint URL is missing.")
            self.finished.emit()
            return
        
        url = self.endpoint.rstrip("/") + "/api/models"
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        try:
            logging.info(f"Worker fetching models from {url}")# 프록시 설정에 따라 요청
            if not self.proxy_disabled:
                response = requests.get(url, headers=headers, timeout=10, verify=False, proxies={"http": Proxy_http, "https": Proxy_https})
            else:
                response = requests.get(url, headers=headers, timeout=10)

            response.raise_for_status()
            res_text = response.content.decode("utf-8")
            res_js = json.loads(res_text)
            
            models_data = []
            if isinstance(res_js, list):
                models_data = res_js
            elif isinstance(res_js, dict):
                if "data" in res_js and isinstance(res_js["data"], list):
                    models_data = res_js["data"]
                elif "models" in res_js and isinstance(res_js["models"], list):
                    models_data = res_js["models"]
            
            models = []
            for model_item in models_data:
                if isinstance(model_item, dict):
                    models.append({
                        "id": model_item.get("id", model_item.get("name", "")),
                        "name": model_item.get("name", model_item.get("id", ""))
                    })
                elif isinstance(model_item, str):
                    models.append({"id": model_item, "name": model_item})
            
            self.models_fetched.emit(models)
            
        except requests.exceptions.RequestException as e:
            self.error.emit(f"Network error fetching models: {e}")
        except json.JSONDecodeError:
            self.error.emit("Invalid JSON response fetching models.")
        except Exception as e:
            self.error.emit(f"Unexpected error fetching models: {e}")
        finally:
            self.finished.emit()

    @Slot()
    def run_chat_stream(self):
        if not self.endpoint or not self.model or not self.messages:
            self.error.emit("Missing endpoint, model, or messages for chat.")
            self.finished.emit()
            return
        
        url = self.endpoint.rstrip("/") + "/api/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        payload = {"model": self.model, "messages": self.messages, "stream": True}
        
        try:
            logging.info(f"Worker sending chat request with {len(self.messages)} messages.")
            # 프록시 설정에 따라 요청
            if not self.proxy_disabled:
                with requests.post(url, headers=headers, json=payload, stream=True, timeout=300,verify=False, proxies={"http": Proxy_http, "https": Proxy_https}) as response:
                    self._process_stream_response(response)
            else:
                with requests.post(url, headers=headers, json=payload, stream=True, timeout=300) as response:
                    self._process_stream_response(response)

                
                    
        except requests.exceptions.Timeout:
            self.error.emit("Connection timed out.")
        except requests.exceptions.RequestException as e:
            error_detail = response.text if response else "Unknown error"
            logging.error(f"Network error during chat: {e}. Details: {error_detail}")
            self.error.emit(f"Network error: {e}\n{error_detail[:200]}")
        except Exception as e:
            logging.error(f"Unexpected error during chat: {e}", exc_info=True)
            self.error.emit(f"Unexpected error: {e}")
        finally:
            self.stream_finished.emit()
            self.finished.emit()

    @Slot()
    def stop(self):
        self._running = False
        logging.info("WebUIWorker stop requested.")

    def _process_stream_response(self, response):
        response.raise_for_status()
        for line in response.iter_lines(decode_unicode=True):
            if not self._running:
                break
            if line.startswith("data:"):
                json_str = line[len("data:"):].strip()
                if json_str == "[DONE]":
                    break
                if json_str:
                    try:
                        data = json.loads(json_str)
                        if "choices" in data and data["choices"]:
                            delta = data["choices"][0].get("delta", {})
                            message_content = delta.get("content", "")
                            if message_content:
                                self.stream_chunk.emit(message_content)
                    except json.JSONDecodeError:
                        logging.warning(f"JSON decode error in stream line: {line}")
                    except Exception as e:
                        logging.error(f"Error processing stream part: {e} - Line: {line}")



# --- 수정사항 2: Assistant에서 Upload File 버튼 및 기능 제거 ---

class AssistantWidget(QWidget):
    send_conversation_signal = Signal(list)
    web_search_signal = Signal(str)  # 웹 검색 요청 시그널
    summarize_conversation_signal = Signal()  # 대화 요약 시그널
    def __init__(self, parent=None):
        super().__init__(parent)
        self.conversation_history = []
        self.summarized_history = ""
        self.current_assistant_response = ""
        self.uploaded_files = []
        self.proxy_disabled = True
        self.Proxy_http = "http://168.219.61.252:8080"
        self.Proxy_https = "http://168.219.61.252:8080"
        self.google_api_key = ""
        self.google_cx = ""
        # 메인 레이아웃
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        # 타이틀과 버튼 레이아웃
        title_layout = QHBoxLayout()
        title_layout.addWidget(QLabel("Assistant"))
        title_layout.addStretch()
        self.new_chat_button = QPushButton("New Chat")
        self.new_chat_button.setToolTip("Start a new conversation")
        title_layout.addWidget(self.new_chat_button)
        layout.addLayout(title_layout)
        # 대화 뷰
        self.conversation_view = QPlainTextEdit()
        self.conversation_view.setReadOnly(True)
        self.conversation_view.setAcceptDrops(True)
        layout.addWidget(self.conversation_view)
        # 파일 업로드 및 도구 영역
        tools_layout = QHBoxLayout()
        # Upload File 버튼 제거
        self.search_button = QPushButton("Web Search")
        self.search_button.setToolTip("Search the web for information")
        # 추가기능 버튼 - 요약
        self.summarize_button = QPushButton("Summarize")
        self.summarize_button.setToolTip("Summarize the conversation")
        tools_layout.addWidget(self.search_button)
        tools_layout.addWidget(self.summarize_button)
        tools_layout.addStretch()
        layout.addLayout(tools_layout)
        # 파일 업로드 표시 영역
        self.uploads_list = QListWidget()
        self.uploads_list.setMaximumHeight(80)
        self.uploads_list.setVisible(False)
        layout.addWidget(self.uploads_list)
        # 프롬프트 입력 영역
        prompt_layout = QHBoxLayout()
        self.prompt_input = QLineEdit()
        self.prompt_input.setPlaceholderText("Enter your prompt...")
        self.prompt_input.setAcceptDrops(True)
        self.send_button = QPushButton("Send")
        prompt_layout.addWidget(self.prompt_input)
        prompt_layout.addWidget(self.send_button)
        layout.addLayout(prompt_layout)
        # 시그널 연결
        self.send_button.clicked.connect(self.send_prompt)
        self.prompt_input.returnPressed.connect(self.send_prompt)
        self.new_chat_button.clicked.connect(self.clear_conversation)
        # upload_button.clicked.connect(self.open_file_dialog) 제거
        self.search_button.clicked.connect(self.handle_web_search)
        self.summarize_button.clicked.connect(self.handle_summarize)
        # 드래그 앤 드롭 설정
        self.setAcceptDrops(True)
        self.conversation_view.installEventFilter(self)
        self.prompt_input.installEventFilter(self)
    
    def eventFilter(self, obj, event):
        # 드래그 앤 드롭 이벤트 처리
        if event.type() == QEvent.DragEnter:
            if event.mimeData().hasUrls():
                event.acceptProposedAction()
                return True
        elif event.type() == QEvent.Drop:
            if event.mimeData().hasUrls():
                urls = event.mimeData().urls()
                for url in urls:
                    file_path = url.toLocalFile()
                    if os.path.isfile(file_path):
                        self.handle_file_upload(file_path)
                event.acceptProposedAction()
                return True
        
        return super().eventFilter(obj, event)
    
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            for url in urls:
                file_path = url.toLocalFile()
                if os.path.isfile(file_path):
                    self.handle_file_upload(file_path)
            event.acceptProposedAction()
    
    def open_file_dialog(self):
        file_dialog = QFileDialog()
        file_paths, _ = file_dialog.getOpenFileNames(self, "Select Files")
        
        for file_path in file_paths:
            self.handle_file_upload(file_path)
    
    def handle_file_upload(self, file_path):
        # 파일 크기 확인
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            QMessageBox.warning(self, "File Too Large", f"File exceeds maximum size of {MAX_FILE_SIZE/1024/1024}MB")
            return
        
        # 지원하는 파일 유형 확인
        file_name = os.path.basename(file_path)
        file_ext = os.path.splitext(file_name)[1].lower()
        
        # 파일 처리
        try:
            file_content = ""
            
            # 텍스트 파일 처리
            if file_ext in ['.txt', '.md', '.py', '.js', '.html', '.css', '.json', '.csv']:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_content = f.read()
                file_type = "text"
            
            # 이미지 파일 처리
            elif file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
                pixmap = QPixmap(file_path)
                if not pixmap.isNull():
                    buffer = QBuffer()
                    buffer.open(QIODevice.WriteOnly)
                    pixmap.save(buffer, "PNG")
                    img_data = buffer.data()
                    file_content = base64.b64encode(img_data).decode('utf-8')
                    file_type = "image"
                else:
                    QMessageBox.warning(self, "Invalid Image", "Could not load the image file.")
                    return
            
            # PDF나 다른 바이너리 파일 처리 (여기서는 바이너리 데이터로 처리)
            else:
                with open(file_path, 'rb') as f:
                    binary_data = f.read()
                    file_content = base64.b64encode(binary_data).decode('utf-8')
                file_type = "binary"
            
            # 파일 정보 저장
            file_info = {
                "name": file_name,
                "path": file_path,
                "type": file_type,
                "content": file_content
            }
            
            self.uploaded_files.append(file_info)
            
            # UI 업데이트
            item = QListWidgetItem(f"{file_name} ({file_type})")
            self.uploads_list.addItem(item)
            self.uploads_list.setVisible(True)
            
            # 대화에 파일 업로드 표시
            self.append_text_to_view(f"\n**You uploaded:** {file_name}\n")
            
        except Exception as e:
            QMessageBox.warning(self, "File Upload Error", f"Error processing file: {str(e)}")
    
    def handle_web_search(self):
        query = self.prompt_input.text().strip()
        if not query:
            QMessageBox.warning(self, "Empty Search", "Please enter a search query.")
            return
        
        if not self.google_api_key or not self.google_cx:
            QMessageBox.warning(self, "API Keys Missing", "Google API Key and Custom Search Engine ID are required for web search. Please configure them in settings.")
            return
        
        self.web_search_signal.emit(query)
        self.append_text_to_view(f"\n**Searching the web for:** {query}\n")
        self.prompt_input.clear()
    
    def perform_web_search(self, query):
        try:
            search_results = search_google(query, self.google_api_key, self.google_cx)
            
            if not search_results:
                self.append_text_to_view("\n**No search results found.**\n")
                return
            
            results_text = "\n**Web Search Results:**\n\n"
            for i, result in enumerate(search_results, 1):
                results_text += f"{i}. **{result['title']}**\n"
                results_text += f"   {result['link']}\n"
                results_text += f"   {result['snippet']}\n\n"
            
            self.append_text_to_view(results_text)
            
            # 검색 결과를 대화 히스토리에 추가
            self.conversation_history.append({
                "role": "system",
                "content": f"Web search results for query '{query}': {json.dumps(search_results)}"
            })
            
        except Exception as e:
            logging.error(f"Error performing web search: {e}")
            self.append_text_to_view(f"\n**Error performing web search:** {str(e)}\n")
    
    def handle_summarize(self):
        if len(self.conversation_history) < 3:
            QMessageBox.information(self, "Not Enough Content", "The conversation is too short to summarize.")
            return
        
        self.summarize_conversation_signal.emit()
        self.append_text_to_view("\n**Summarizing the conversation...**\n")
    
    def summarize_conversation(self):
        try:
            if not self.conversation_history:
                return
            
            # 대화 요약을 위한 프롬프트 생성
            summary_prompt = "Please summarize our conversation so far concisely, capturing the key points and important information. Focus on the main topics and conclusions."
            
            # 요약 요청을 대화 히스토리에 추가
            self.conversation_history.append({"role": "user", "content": summary_prompt})
            
            # 대화 전송 (이 부분은 요약 완료 후 자동으로 처리됨)
            self.send_conversation_signal.emit(self.conversation_history)
            
            # 요약이 완료되면 handle_stream_finished에서 추가 처리
            
        except Exception as e:
            logging.error(f"Error summarizing conversation: {e}")
            self.append_text_to_view(f"\n**Error during summarization:** {str(e)}\n")
    
    def process_youtube_links(self, text):
        # YouTube 링크 감지 및 처리
        youtube_pattern = r"(?:https?:\/\/)?(?:www\.)?(?:youtube\.com\/watch\?v=|youtu\.be\/)([a-zA-Z0-9_-]{11})"
        youtube_matches = re.findall(youtube_pattern, text)
        
        if youtube_matches:
            for video_id in youtube_matches:
                try:
                    self.append_text_to_view(f"\n**Processing YouTube video transcript:** https://youtube.com/watch?v={video_id}\n")
                    if self.proxy_disabled:
                        transcript = get_youtube_transcript(video_id)
                    else:
                        transcript = get_youtube_transcript(video_id,proxy_disabled=self.proxy_disabled,Proxy_http=self.Proxy_http,Proxy_https=self.Proxy_https)
                    
                    
                    # 트랜스크립트를 대화 히스토리에 추가
                    self.conversation_history.append({
                        "role": "system",
                        "content": f"Transcript from YouTube video (ID: {video_id}): {transcript}"
                    })
                    
                    self.append_text_to_view(f"\n**YouTube transcript extracted.** Length: {len(transcript)} characters.\n")
                    
                except Exception as e:
                    logging.error(f"Error processing YouTube transcript: {e}")
                    self.append_text_to_view(f"\n**Error extracting YouTube transcript:** {str(e)}\n")
            
            return True
        
        return False

    def send_prompt(self):
        prompt_text = self.prompt_input.text().strip()
        if not prompt_text:
            return
        
        # YouTube 링크 처리
        has_youtube = self.process_youtube_links(prompt_text)
        
        # 대화 뷰에 추가
        self.append_text_to_view(f"\n**You:** {prompt_text}\n**Assistant:** ")
        
        # 업로드된 파일이 있으면 처리
        file_content = ""
        if self.uploaded_files:
            for file_info in self.uploaded_files:
                if file_info["type"] == "text":
                    file_content += f"\nContent of file '{file_info['name']}':\n{file_info['content']}\n"
                elif file_info["type"] == "image":
                    # 이미지는 별도 처리가 필요할 수 있음
                    file_content += f"\nAn image file was uploaded: '{file_info['name']}'. Please analyze its content.\n"
                else:
                    file_content += f"\nA binary file was uploaded: '{file_info['name']}'.\n"
            
            # 프롬프트에 파일 정보 추가
            prompt_with_files = f"{prompt_text}\n\n{file_content}"
            self.conversation_history.append({"role": "user", "content": prompt_with_files})
            
            # 파일 목록 초기화
            self.uploaded_files = []
            self.uploads_list.clear()
            self.uploads_list.setVisible(False)
        else:
            # 일반 프롬프트만 추가
            self.conversation_history.append({"role": "user", "content": prompt_text})
        
        # Clear input and disable send button
        self.prompt_input.clear()
        self.send_button.setEnabled(False)
        self.new_chat_button.setEnabled(False)
        # Reset buffer for assistant response
        self.current_assistant_response = ""
        
        # 대화가 너무 길어지면 요약 처리
        if len(self.conversation_history) > MAX_CONVERSATION_LENGTH and not self.summarized_history:
            self.summarize_conversation()
        else:
            # 대화 전송
            self.send_conversation_signal.emit(self.conversation_history)

    @Slot(str)
    def append_text_to_view(self, text):
        self.conversation_view.moveCursor(QTextCursor.End)
        self.conversation_view.insertPlainText(text)
        self.conversation_view.moveCursor(QTextCursor.End)

    @Slot(str)
    def handle_stream_chunk(self, chunk):
        self.append_text_to_view(chunk)
        self.current_assistant_response += chunk

    @Slot()
    def clear_conversation(self):
        self.conversation_view.clear()
        self.prompt_input.clear()
        self.conversation_history = []
        self.summarized_history = ""
        self.current_assistant_response = ""
        self.send_button.setEnabled(True)
        self.new_chat_button.setEnabled(True)
        self.uploaded_files = []
        self.uploads_list.clear()
        self.uploads_list.setVisible(False)
        logging.info("Assistant conversation cleared.")

    @Slot()
    def on_stream_finished(self):
        if self.current_assistant_response:
            # 요약 요청에 대한 응답인지 확인
            last_user_msg = next((msg for msg in reversed(self.conversation_history) 
                                  if msg.get("role") == "user"), None)
            
            if last_user_msg and "summarize our conversation" in last_user_msg.get("content", "").lower():
                # 요약 응답 처리
                self.conversation_history.append({"role": "assistant", "content": self.current_assistant_response})
                self.summarized_history = self.current_assistant_response
                
                # 요약 후 대화 히스토리 정리
                self.conversation_history = [
                    {"role": "system", "content": f"Previous conversation summary: {self.summarized_history}"}
                ]
                
                logging.info("Conversation summarized and history reset.")
            else:
                # 일반 응답 처리
                self.conversation_history.append({"role": "assistant", "content": self.current_assistant_response})
        
        self.send_button.setEnabled(True)
        self.new_chat_button.setEnabled(True)
        self.append_text_to_view("\n")
        logging.info(f"Assistant stream finished. History size: {len(self.conversation_history)}")

# --- Main Window (MODIFIED for Sidebar and Tray Icon) ---
class MainWindow(QMainWindow):
    send_p2p_data_signal = Signal(dict)
    start_webui_chat_signal = Signal(str, str, str, list)
    perform_web_search_signal = Signal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SideBar Assistant - P2P")
        # Initial flags: Frameless, StaysOnTop. Tool for taskbar icon handled later.
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.settings = QSettings(SETTINGS_ORG, SETTINGS_APP)
        self.notes_directory = ""
        self.webui_endpoint = ""
        self.webui_apikey = ""
        self.webui_model = ""
        self.google_api_key = ""
        self.google_cx = ""
        
        
        
        self.clipboard_history = []
        self.monitoring_clipboard = True
        self.current_processes = {}
        self.notes_changed = {}
        self.note_save_timer = QTimer(self)
        self.note_save_timer.setInterval(5000)
        self.note_save_timer.setSingleShot(True)
        self.note_save_timer.timeout.connect(self.save_current_note_if_changed)
        self.needs_sync = False
        self.allow_close = False
        
        self.central_widget = QSplitter(Qt.Vertical)
        self.setCentralWidget(self.central_widget)
        
        self.clipboard_widget = self.create_clipboard_widget()
        self.process_widget = self.create_process_widget()
        self.notepad_widget = self.create_notepad_widget()
        self.assistant_widget = AssistantWidget()
        
        self.central_widget.addWidget(self.clipboard_widget)
        self.central_widget.addWidget(self.process_widget)
        self.central_widget.addWidget(self.notepad_widget)
        self.central_widget.addWidget(self.assistant_widget)
        self.load_settings()
        self.load_splitter_state()
        self.set_default_splitter_sizes()
        
        self.status_bar = self.statusBar()
        
        try:
            self.clipboard = QGuiApplication.clipboard()
            self.clipboard.dataChanged.connect(self.on_clipboard_changed)
            self.on_clipboard_changed() # Initial check
        except Exception as e:
            logging.error(f"Failed to setup clipboard monitoring: {e}")
            QMessageBox.critical(self, "Error", "Failed to access clipboard.")
        
        self.process_timer = QTimer(self)
        self.process_timer.timeout.connect(self.update_process_list)
        self.process_timer.start(1000)
        self.update_process_list()
        
        self.setup_clipboard_shortcuts()
        self.apply_stylesheet()
        self.load_notes()
        
        # P2P Manager 설정
        self.p2p_thread = QThread(self)
        self.p2p_manager = P2PManager(self.settings)
        self.p2p_manager.moveToThread(self.p2p_thread)
        self.p2p_thread.started.connect(self.p2p_manager.start)
        self.p2p_manager.log_message.connect(self.log_status)
        self.p2p_manager.peer_status_changed.connect(self.update_peer_status_ui)
        self.p2p_manager.received_data.connect(self.handle_received_p2p_data)
        self.send_p2p_data_signal.connect(self.p2p_manager.send_to_all_peers)
        self.p2p_thread.start()
        
        # WebUI Worker 설정
        self.webui_thread = QThread(self)
        self.webui_worker = None
        self.assistant_widget.send_conversation_signal.connect(self.handle_assistant_conversation)
        self.assistant_widget.web_search_signal.connect(self.handle_web_search)
        self.assistant_widget.summarize_conversation_signal.connect(self.handle_summarize_conversation)
        self.start_webui_chat_signal.connect(self.start_webui_chat_worker)
        self.perform_web_search_signal.connect(self.assistant_widget.perform_web_search)
        
        # 트레이 아이콘 생성
        self.create_tray_icon()
        
        # 자동 숨김 설정
        self.auto_hide_timer = QTimer(self)
        self.auto_hide_timer.setInterval(250)
        self.auto_hide_timer.timeout.connect(self.check_mouse_position_for_auto_hide)
        self.is_mouse_over_window = False
        self.auto_hide_enabled = self.settings.value("window/autoHide", defaultValue=True, type=bool)
        
        if hasattr(self, 'auto_hide_action'):
            self.auto_hide_action.setChecked(self.auto_hide_enabled)
        
        if self.auto_hide_enabled:
            self.auto_hide_timer.start()
        
        self.position_as_sidebar()
        self.installEventFilter(self)
        
        # Google API 키 설정 전달
        self.assistant_widget.google_api_key = self.google_api_key
        self.assistant_widget.google_cx = self.google_cx
        
        self.update_assistant_availability()
        
        logging.info("MainWindow initialized.")
        
        # 초기 표시 설정
        if self.auto_hide_enabled:
            self.hide()
            QTimer.singleShot(100, self.check_mouse_position_for_auto_hide)
        else:
            self.show_window()

    def load_settings(self):
        logging.info("Loading settings...")
        default_notes_dir = os.path.join(QStandardPaths.writableLocation(QStandardPaths.AppDataLocation), SETTINGS_APP, "Notes")
        self.notes_directory = self.settings.value("notesDirectory", defaultValue=default_notes_dir)
        
        try:
            if not os.path.exists(self.notes_directory):
                os.makedirs(self.notes_directory)
                logging.info(f"Created notes directory: {self.notes_directory}")
        except Exception as e:
            logging.error(f"Failed to create notes directory {self.notes_directory}: {e}")
            self.notes_directory = default_notes_dir 
            try:
                os.makedirs(self.notes_directory, exist_ok=True) 
            except:
                pass
        
        self.webui_endpoint = self.settings.value("webui/endpoint", defaultValue="")
        self.webui_apikey = self.settings.value("webui/apikey", defaultValue="")
        self.webui_model = self.settings.value("webui/selected_model", defaultValue="")
        # 프록시 설정 로드
        self.proxy_disabled = self.settings.value("webui/disable_proxy", defaultValue=False, type=bool)
        self.assistant_widget.proxy_disabled = self.proxy_disabled
        
        # Google API 설정 로드
        self.google_api_key = self.settings.value("google/apikey", defaultValue="")
        self.google_cx = self.settings.value("google/cx", defaultValue="")
        
        self.auto_hide_enabled = self.settings.value("window/autoHide", defaultValue=True, type=bool)
        
        current_always_on_top = bool(self.windowFlags() & Qt.WindowStaysOnTopHint)
        saved_always_on_top = self.settings.value("window/alwaysOnTop", defaultValue=False, type=bool)
        
        if current_always_on_top != saved_always_on_top:
            self.toggle_always_on_top(saved_always_on_top, save_setting=False)

    @Slot()
    def settings_updated(self):
        logging.info("Settings updated, reloading configuration...")
        old_notes_dir = self.notes_directory
        
        if self.p2p_manager and self.p2p_thread.isRunning():
            logging.info("Stopping P2P Manager for settings update...")
            self.p2p_manager.stop()
        
        self.load_settings()
        
        if old_notes_dir != self.notes_directory:
            self.save_all_notes()
            self.load_notes()
        
        # P2P Manager 재시작
        if self.settings.value("p2p/enabled", defaultValue=False, type=bool):
            logging.info("Restarting P2P Manager due to settings change...")
            QTimer.singleShot(500, lambda: self.p2p_manager.start() if self.p2p_manager else None)
        else:
            if self.p2p_manager and self.p2p_manager.running:
                 self.p2p_manager.stop()
        
        # Google API 키 업데이트
        self.assistant_widget.google_api_key = self.google_api_key
        self.assistant_widget.google_cx = self.google_cx
        
        self.update_assistant_availability()
        
        if hasattr(self, 'auto_hide_action'):
            self.auto_hide_action.setChecked(self.auto_hide_enabled)
            self.toggle_auto_hide(self.auto_hide_enabled, save_setting=False)
        
        if hasattr(self, 'always_on_top_action'):
            self.always_on_top_action.setChecked(self.settings.value("window/alwaysOnTop", defaultValue=True, type=bool))

    def create_clipboard_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.addWidget(QLabel("Clipboard History (Max 30)"))
        
        self.clipboard_list = QListWidget()
        self.clipboard_list.setIconSize(QSize(64, 64))
        self.clipboard_list.itemDoubleClicked.connect(self.on_clipboard_item_activated)
        
        layout.addWidget(self.clipboard_list)
        return widget

    def create_process_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.addWidget(QLabel("Process Manager"))
        
        search_layout = QHBoxLayout()
        self.process_search_input = QLineEdit()
        self.process_search_input.setPlaceholderText("Search PID or Name...")
        self.process_search_input.textChanged.connect(self.filter_process_list_ui)
        
        kill_button = QPushButton("Kill Selected")
        kill_button.clicked.connect(self.kill_selected_processes)
        
        search_layout.addWidget(self.process_search_input)
        search_layout.addWidget(kill_button)
        
        layout.addLayout(search_layout)
        
        self.process_list = QListWidget()
        self.process_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        
        layout.addWidget(self.process_list)
        
        port_finder_group = QGroupBox("Find Process by Port")
        port_finder_layout = QHBoxLayout(port_finder_group)
        port_finder_layout.addWidget(QLabel("Port:"))
        
        self.port_search_input = QLineEdit()
        self.port_search_input.setPlaceholderText("Enter port number...")
        self.port_search_input.setFixedWidth(120)
        
        find_port_button = QPushButton("Find Process")
        find_port_button.clicked.connect(self.find_process_by_port)
        
        port_finder_layout.addWidget(self.port_search_input)
        port_finder_layout.addWidget(find_port_button)
        port_finder_layout.addStretch()
        
        layout.addWidget(port_finder_group)
        
        return widget

    def create_notepad_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        
        self.notepad_tabs = QTabWidget()
        self.notepad_tabs.setTabsClosable(True)
        self.notepad_tabs.setMovable(True)
        self.notepad_tabs.tabCloseRequested.connect(self.close_notepad_tab)
        self.notepad_tabs.currentChanged.connect(self.on_notepad_tab_changed)
        self.notepad_tabs.tabBar().setContextMenuPolicy(Qt.CustomContextMenu)
        self.notepad_tabs.tabBar().customContextMenuRequested.connect(self.show_notepad_tab_context_menu)
        
        button_layout = QHBoxLayout()
        add_tab_button = QPushButton("+")
        add_tab_button.setToolTip("Add New Note")
        add_tab_button.setFixedSize(40, 25)
        add_tab_button.clicked.connect(lambda: self.add_new_notepad_tab())
        
        button_layout.addWidget(add_tab_button)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        layout.addWidget(self.notepad_tabs)
        
        return widget

    def update_assistant_availability(self):
        """Enable/disable assistant based on settings."""
        # 기본값이 있으므로 항상 활성화
        self.assistant_widget.setEnabled(True)
        self.assistant_widget.prompt_input.setPlaceholderText("Enter your prompt...")
        logging.info("Assistant enabled with default settings")

    @Slot(list)
    def handle_assistant_conversation(self, messages):
        # endpoint가 설정되어 있지 않은 경우 기본값 사용
        endpoint = self.webui_endpoint if self.webui_endpoint else DEFAULT_WEBUI_ENDPOINT
        api_key = self.webui_apikey if self.webui_apikey else DEFAULT_WEBUI_API_KEY
        model = self.webui_model if self.webui_model else DEFAULT_WEBUI_MODEL
        
        if self.webui_worker and self.webui_thread.isRunning():
            logging.warning("Assistant is already processing a request.")
            return
        
        self.start_webui_chat_signal.emit(endpoint, api_key, model, messages)

    @Slot(str)
    def handle_web_search(self, query):
        if not self.google_api_key or not self.google_cx:
            QMessageBox.warning(self, "Search Error", "Google API Key and Custom Search ID not configured in Settings.")
            return
        
        self.perform_web_search_signal.emit(query)

    @Slot()
    def handle_summarize_conversation(self):
        if self.webui_worker and self.webui_thread.isRunning():
            logging.warning("Assistant is already processing a request.")
            return
        
        self.assistant_widget.summarize_conversation()

    @Slot(str, str, str, list)
    def start_webui_chat_worker(self, endpoint, api_key, model, messages):
        if self.webui_worker and self.webui_thread.isRunning():
            logging.warning("Stopping lingering WebUI worker before starting new one.")
            self.webui_worker.stop()
            self.webui_thread.quit()
            self.webui_thread.wait(500)
        
        # 프록시 설정을 포함하여 Worker 생성
        self.webui_worker = WebUIWorker(endpoint, api_key, model, messages, self.proxy_disabled)
        self.webui_worker.moveToThread(self.webui_thread)
        
        try:
            self.webui_worker.stream_chunk.disconnect() 
        except RuntimeError:
            pass
        
        try:
            self.webui_worker.stream_finished.disconnect() 
        except RuntimeError:
            pass
        
        try:
            self.webui_worker.error.disconnect() 
        except RuntimeError:
            pass
        
        try:
            self.webui_worker.finished.disconnect() 
        except RuntimeError:
            pass
        
        self.webui_worker.stream_chunk.connect(self.assistant_widget.handle_stream_chunk)
        self.webui_worker.stream_finished.connect(self.assistant_widget.on_stream_finished)
        self.webui_worker.error.connect(self.handle_webui_error)
        self.webui_worker.finished.connect(self.webui_thread.quit)
        self.webui_worker.finished.connect(self.webui_worker.deleteLater)
        
        self.webui_thread.started.connect(self.webui_worker.run_chat_stream)
        self.webui_thread.finished.connect(lambda: setattr(self, 'webui_worker', None))
        
        self.webui_thread.start()
        logging.info(f"WebUI chat worker started (proxy {'disabled' if self.proxy_disabled else 'enabled'}).")

    @Slot(str)
    def handle_webui_error(self, error_message):
        logging.error(f"WebUI Worker Error: {error_message}")
        QMessageBox.critical(self, "Assistant Error", f"An error occurred:\n{error_message}")
        if self.assistant_widget:
            self.assistant_widget.on_stream_finished()

    def position_as_sidebar(self):
        try:
            screen = QGuiApplication.primaryScreen()
            if not screen:
                return
            
            available_geo = screen.availableGeometry()
            window_height = available_geo.height()
            
            # Position at the right edge
            self.setGeometry(available_geo.width() - SIDEBAR_WIDTH, available_geo.top(), SIDEBAR_WIDTH, window_height)
            
        except Exception as e:
            logging.error(f"Error positioning window: {e}")
            self.resize(SIDEBAR_WIDTH, 800) # Fallback size

    def load_splitter_state(self):
        try:
            # 이전에 저장된 크기 불러오기
            saved_sizes = self.settings.value("window/splitterSizes")
            if isinstance(saved_sizes, list) and len(saved_sizes) == 4 and all(isinstance(size, int) for size in saved_sizes):
                self.central_widget.setSizes(saved_sizes)
                logging.info(f"Restored splitter sizes: {saved_sizes}")
                return
            
            # 기존 상태 복원 시도
            state = self.settings.value("window/splitterState")
            if isinstance(state, QByteArray) and not state.isEmpty():
                if self.central_widget.restoreState(state):
                    logging.info("Restored splitter state.")
                    self.adjust_splitter_sizes()
                    return
                else:
                    logging.warning("Failed to restore splitter state, using defaults.")
            else:
                logging.info("No saved splitter state found, using defaults.")
            self.set_default_splitter_sizes()
        except Exception as e:
            logging.error(f"Error loading splitter state: {e}")
            self.set_default_splitter_sizes()

    def set_default_splitter_sizes(self):
        total_height = self.central_widget.height()
        if total_height <= 0:
            total_height = 800 # Fallback if height not determined yet
        sizes = [
            int(total_height * 0.25),
            int(total_height * 0.1),
            int(total_height * 0.4),
            int(total_height * 0.25)
        ]
        self.central_widget.setSizes(sizes)
        logging.info(f"Set default splitter sizes: {sizes}")

    def save_splitter_state(self):
        try:
            # 상태와 크기 모두 저장
            state = self.central_widget.saveState()
            sizes = self.central_widget.sizes()
            self.settings.setValue("window/splitterState", state)
            self.settings.setValue("window/splitterSizes", sizes)
            logging.info(f"Saved splitter state and sizes: {sizes}")
        except Exception as e:
            logging.error(f"Error saving splitter state: {e}")

    def adjust_splitter_sizes(self):
        sizes = self.central_widget.sizes()
        if len(sizes) != 4: 
            logging.warning("Splitter size count mismatch, resetting to defaults.")
            self.set_default_splitter_sizes()
            return
        
        total_height = self.central_widget.height()
        current_sum = sum(sizes)
        
        if total_height <= 0 or current_sum <= 0:
            return
        
        if abs(current_sum - total_height) > 10:
            scale_factor = total_height / current_sum
            new_sizes = [max(10, int(s * scale_factor)) for s in sizes]
            new_sizes[-1] = max(10, total_height - sum(new_sizes[:-1]))
            
            if sum(new_sizes) == total_height and all(s >= 10 for s in new_sizes):
                self.central_widget.setSizes(new_sizes)
                logging.debug(f"Adjusted splitter sizes proportionally: {new_sizes}")
            else:
                self.set_default_splitter_sizes()

    def save_splitter_state(self):
        try:
            state = self.central_widget.saveState()
            self.settings.setValue("window/splitterState", state)
            logging.info("Saved splitter state.")
        except Exception as e:
            logging.error(f"Error saving splitter state: {e}")

    def apply_stylesheet(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #f8f9fa; }
            QSplitter::handle { background-color: #ced4da; height: 3px; }
            QSplitter::handle:hover { background-color: #adb5bd; }
            QSplitter::handle:pressed { background-color: #6c757d; }
            QPushButton { background-color: #e9ecef; border: 1px solid #ced4da; padding: 6px 12px; border-radius: 4px; color: #495057; }
            QPushButton:hover { background-color: #dee2e6; }
            QPushButton:pressed { background-color: #ced4da; }
            QLineEdit, QTextEdit, QListWidget, QPlainTextEdit, QComboBox { border: 1px solid #ced4da; padding: 5px; background-color: #ffffff; border-radius: 4px; color: #212529; }
            QLabel { color: #495057; font-weight: bold; padding-bottom: 5px; }
            QListWidget { background-color: #f8f9fa; }
            QListWidget::item { padding: 5px; border-bottom: 1px solid #eee; }
            QListWidget::item:selected { background-color: #cfe2ff; color: #000; border-bottom: 1px solid #b9d4ff; }
            QListWidget::item:selected:!active { background-color: #e0e0e0; color: #000; }
            QStatusBar { background-color: #e9ecef; color: #495057; }
            QTabWidget::pane { border: 1px solid #dee2e6; background-color: #ffffff; border-radius: 4px; }
            QTabBar::tab { background: #e9ecef; border: 1px solid #dee2e6; border-bottom: none; padding: 6px 10px; min-width: 60px; border-top-left-radius: 4px; border-top-right-radius: 4px; }
            QTabBar::tab:selected { background: #ffffff; }
            QTabBar::tab:hover { background: #f1f3f5; }
            QTabBar::tab:selected[data-unsaved="true"] { font-style: italic; color: #0056b3; }
            QTabBar::tab:!selected[data-unsaved="true"] { font-style: italic; color: #007bff; }
            QGroupBox { margin-top: 10px; }
            QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 3px; }
            QPlainTextEdit { background-color: #f8f9fa; }
            QProgressBar { border: 1px solid #ced4da; border-radius: 4px; text-align: center; background-color: #f8f9fa; }
            QProgressBar::chunk { background-color: #0d6efd; width: 10px; margin: 0.5px; }
        """)

    def create_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        pixmap = QPixmap(16, 16)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setBrush(Qt.blue) # Simple icon
        painter.drawEllipse(0, 0, 15, 15)
        painter.end()
        icon = QIcon(pixmap)
        self.tray_icon.setIcon(icon)
        self.tray_icon.setToolTip("SideBar Assistant - P2P")
        
        tray_menu = QMenu()
        show_action = QAction("Show", self, triggered=self.show_window)
        hide_action = QAction("Hide", self, triggered=self.hide_window)
        
        self.always_on_top_action = QAction("Always on Top", self, checkable=True)
        self.always_on_top_action.setChecked(self.settings.value("window/alwaysOnTop", defaultValue=True, type=bool))
        self.always_on_top_action.triggered.connect(lambda checked: self.toggle_always_on_top(checked, save_setting=True))
        
        self.auto_hide_action = QAction("Auto Hide Sidebar", self, checkable=True)
        self.auto_hide_action.setChecked(self.auto_hide_enabled)
        self.auto_hide_action.triggered.connect(lambda checked: self.toggle_auto_hide(checked, save_setting=True))
        
        settings_action = QAction("Settings...", self, triggered=self.open_settings_dialog)
        quit_action = QAction("Quit", self, triggered=self.quit_application)
        
        tray_menu.addAction(show_action)
        tray_menu.addAction(hide_action)
        tray_menu.addSeparator()
        tray_menu.addAction(self.always_on_top_action)
        tray_menu.addAction(self.auto_hide_action)
        tray_menu.addSeparator()
        tray_menu.addAction(settings_action)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_activated)
        self.tray_icon.show()
        
        # Apply initial always_on_top state
        self.toggle_always_on_top(self.always_on_top_action.isChecked(), save_setting=False)

    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self.toggle_window_visibility()

    def show_window(self):
        # Determine the correct flags for a frameless tool window
        flags = Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint
        self.setWindowFlags(flags)
        self.show()
        self.activateWindow()
        self.raise_()

    def hide_window(self):
        self.hide()
        logging.debug("hide_window called")

    def toggle_window_visibility(self):
        if self.isVisible():
            self.hide_window()
        else:
            self.show_window()

    def toggle_always_on_top(self, checked, save_setting=True):
        flags = self.windowFlags()
        if checked:
            self.setWindowFlags(flags | Qt.WindowStaysOnTopHint)
        else:
            self.setWindowFlags(flags & ~Qt.WindowStaysOnTopHint)
        
        if self.isVisible(): # Re-show to apply flag changes if visible
            self.show()
        
        if save_setting:
            self.settings.setValue("window/alwaysOnTop", checked)
        
        logging.info(f"Always on Top toggled: {checked}")

    def open_settings_dialog(self):
        try:
            dialog = SettingsDialog(self.settings, self)
            dialog.settings_updated_signal.connect(self.settings_updated)
            dialog.exec()
        except Exception as e:
            logging.error(f"Error opening settings dialog: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to open settings: {e}")

    def quit_application(self):
        logging.info("Quit requested.")
        self.allow_close = True
        self.close() # Triggers closeEvent

    # --- Event Handling ---
    def enterEvent(self, event: QEvent):
        if self.auto_hide_enabled:
            self.is_mouse_over_window = True
            logging.debug("Mouse entered window area.")
        super().enterEvent(event)

    def leaveEvent(self, event: QEvent):
        if self.auto_hide_enabled:
            self.is_mouse_over_window = False
            logging.debug("Mouse left window area. Checking for auto-hide.")
            QTimer.singleShot(50, self.check_mouse_position_for_auto_hide)
        super().leaveEvent(event)

    def eventFilter(self, obj, event: QEvent):
        # Handle focus out for auto-hide and P2P sync trigger
        if event.type() == QEvent.WindowDeactivate:
            logging.debug("Window deactivated (lost focus).")
            if self.auto_hide_enabled and not self.is_mouse_over_window:
                logging.debug("Window deactivated and mouse not over, hiding.")
                self.hide_window()
            if self.needs_sync:
                self.trigger_sync()
                self.needs_sync = False
        elif event.type() == QApplication.focusChanged:
            if not QGuiApplication.focusWindow():
                logging.debug("Application lost focus.")
                if self.auto_hide_enabled and self.isVisible() and not self.is_mouse_over_window:
                    logging.debug("Application lost focus, sidebar visible, mouse not over -> hiding.")
                    self.hide_window()
        return super().eventFilter(obj, event)

    def closeEvent(self, event: QCloseEvent):
        if self.allow_close:
            logging.info("Closing application...")
            self.save_splitter_state()
            self.save_all_notes()
            
            if self.p2p_manager:
                self.p2p_manager.stop()
            
            if self.p2p_thread.isRunning():
                self.p2p_thread.quit()
                self.p2p_thread.wait(1000)
            
            if self.webui_worker and self.webui_thread.isRunning():
                 self.webui_worker.stop()
                 self.webui_thread.quit()
                 self.webui_thread.wait(1000)
            
            if self.auto_hide_timer.isActive():
                self.auto_hide_timer.stop()
            
            self.tray_icon.hide()
            self.settings.sync()
            
            logging.info("Application closed gracefully.")
            event.accept()
            QApplication.instance().quit()
        else:
            logging.debug("Close event intercepted, hiding window to tray.")
            event.ignore()
            self.hide_window()

    # --- Clipboard Methods ---
    def on_clipboard_changed(self):
        if not self.monitoring_clipboard:
            return
        
        try:
            mime_data = self.clipboard.mimeData()
            if not mime_data:
                return
            
            new_item_data = None
            data_type = None
            current_text = self.clipboard.text()
            current_pixmap = self.clipboard.pixmap()
            
            if mime_data.hasImage() and not current_pixmap.isNull():
                is_new = True
                if self.clipboard_history:
                    last_item = self.clipboard_history[0]
                    if last_item.data_type == "image" and self.pixmaps_equal(last_item.data, current_pixmap):
                        is_new = False
                
                if is_new:
                    new_item_data = current_pixmap
                    data_type = "image"
            
            elif mime_data.hasText() and current_text:
                is_new = True
                if self.clipboard_history:
                    last_item = self.clipboard_history[0]
                    if last_item.data_type == "text" and last_item.data == current_text:
                        is_new = False
                
                if is_new:
                    new_item_data = current_text
                    data_type = "text"
            
            if new_item_data and data_type:
                new_item = ClipboardItem(data_type, new_item_data)
                self.clipboard_history.insert(0, new_item)
                
                if len(self.clipboard_history) > MAX_CLIPBOARD_HISTORY:
                    self.clipboard_history.pop()
                
                self.update_clipboard_list_ui()
                self.schedule_sync("clipboard")
        
        except Exception as e:
            logging.error(f"Error processing clipboard change: {e}", exc_info=True)
    
    def pixmaps_equal(self, p1, p2):
        try:
            if p1.isNull() and p2.isNull():
                return True
            if p1.isNull() or p2.isNull():
                return False
            if p1.cacheKey() == p2.cacheKey():
                return True
            return p1.toImage() == p2.toImage()
        except Exception as e:
            logging.error(f"Error comparing pixmaps: {e}")
            return False
    
    def update_clipboard_list_ui(self):
        try:
            self.clipboard_list.clear()
            for i, item in enumerate(self.clipboard_history):
                list_item = QListWidgetItem()
                
                if item.data_type == "text":
                    preview = item.data.split("\n")[0][:50] + ("..." if len(item.data) > 50 else "")
                    list_item.setText(f"{i+1}. {preview}")
                elif item.data_type == "image":
                    icon = QIcon(item.data.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                    list_item.setIcon(icon)
                    list_item.setText(f"{i+1}. [Image]")
                
                list_item.setData(Qt.UserRole, i)
                self.clipboard_list.addItem(list_item)
        
        except Exception as e:
            logging.error(f"Error updating clipboard UI: {e}", exc_info=True)
    
    def on_clipboard_item_activated(self, item):
        try:
            index = item.data(Qt.UserRole)
            self.copy_item_to_clipboard(index)
        except Exception as e:
            logging.error(f"Error activating clipboard item: {e}", exc_info=True)
    
    def copy_item_to_clipboard(self, index):
        if not (0 <= index < len(self.clipboard_history)):
            return
        
        history_item = self.clipboard_history[index]
        
        try:
            self.monitoring_clipboard = False
            self.clipboard.clear()
            
            mime_data = QMimeData()
            
            if history_item.data_type == "text":
                mime_data.setText(history_item.data)
            elif history_item.data_type == "image":
                mime_data.setImageData(history_item.data.toImage())
                self.clipboard.setPixmap(history_item.data)
            
            self.clipboard.setMimeData(mime_data)
            self.log_status(f"Item {index+1} copied to clipboard.", 3000)
        
        except Exception as e:
            logging.error(f"Error copying item {index+1} to clipboard: {e}", exc_info=True)
            QMessageBox.warning(self, "Error", f"Failed to copy item to clipboard: {e}")
        
        finally:
            QTimer.singleShot(150, lambda: setattr(self, "monitoring_clipboard", True))
    
    def setup_clipboard_shortcuts(self):
        try:
            for i in range(10):
                shortcut = QShortcut(QKeySequence(f"Ctrl+{(i + 1) % 10}"), self)
                shortcut.activated.connect(lambda index_val=i: self.copy_item_to_clipboard(index_val))
                setattr(self, f"shortcut_ctrl_{i}", shortcut)
        except Exception as e:
            logging.error(f"Failed to setup clipboard shortcuts: {e}", exc_info=True)

    # --- Process Manager Methods ---
    def update_process_list(self):
        try:
            new_processes = {}
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    new_processes[proc.info["pid"]] = proc.info["name"]
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            self.current_processes = new_processes
            self.filter_process_list_ui()
        
        except Exception as e:
            logging.error(f"Error updating process list: {e}", exc_info=True)
    
    def filter_process_list_ui(self):
        try:
            search = self.process_search_input.text().lower()
            selected_pids = {item.data(Qt.UserRole) for item in self.process_list.selectedItems()}
            
            self.process_list.clear()
            sorted_processes = sorted(self.current_processes.items(), key=lambda item_val: item_val[1].lower())
            
            for pid, name in sorted_processes:
                if not search or search in str(pid) or search in name.lower():
                    item = QListWidgetItem(f"{pid}: {name}")
                    item.setData(Qt.UserRole, pid)
                    self.process_list.addItem(item)
                    
                    if pid in selected_pids:
                        item.setSelected(True)
        
        except Exception as e:
            logging.error(f"Error filtering process list UI: {e}", exc_info=True)
    
    def kill_selected_processes(self):
        try:
            items = self.process_list.selectedItems()
            if not items:
                return
            
            to_kill = []
            critical = False
            details = []
            
            for item in items:
                pid = item.data(Qt.UserRole)
                name = self.current_processes.get(pid, "Unknown Process")
                is_crit = any(c.lower() in name.lower() for c in CRITICAL_PROCESSES)
                
                to_kill.append({"pid": pid, "name": name})
                details.append(f"- {name} ({pid}){ ' [CRITICAL]' if is_crit else '' }")
                
                if is_crit:
                    critical = True
            
            msg = f"Terminate the following {len(to_kill)} process(es)?\n\n" + "\n".join(details)
            
            if critical:
                msg += "\n\nWARNING: One or more selected processes appear critical..."
                reply = QMessageBox.warning(self, "Critical Process Warning", msg, QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            else:
                reply = QMessageBox.question(self, "Confirm Termination", msg, QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                killed, failed = 0, 0
                
                for p_info in to_kill:
                    try:
                        p = psutil.Process(p_info["pid"])
                        p.terminate()
                        
                        try:
                            p.wait(timeout=0.2)
                            killed += 1
                        except psutil.TimeoutExpired:
                            p.kill()
                            p.wait(timeout=0.2)
                            killed += 1
                    
                    except psutil.NoSuchProcess:
                        killed += 1
                    except psutil.AccessDenied:
                        failed += 1
                    except Exception:
                        failed += 1
                
                self.log_status(f"Process termination: Killed/Exited: {killed}, Failed: {failed}.", 5000)
                self.update_process_list()
        
        except Exception as e:
            logging.error(f"Error during kill process: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Error during process termination: {e}")

    @Slot()
    def find_process_by_port(self):
        port_text = self.port_search_input.text().strip()
        
        if not port_text.isdigit():
            QMessageBox.warning(self, "Invalid Port", "Please enter a valid port number.")
            return
        
        try:
            port = int(port_text)
            if not (1 <= port <= 65535):
                raise ValueError("Port out of range")
        except ValueError:
            QMessageBox.warning(self, "Invalid Port", "Port number must be between 1 and 65535.")
            return
        
        found_pids = set()
        process_info = []
        
        try:
            connections = psutil.net_connections()
            
            for conn in connections:
                if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port and conn.pid:
                    found_pids.add(conn.pid)
            
            if not found_pids:
                QMessageBox.information(self, "Not Found", f"No process found using port {port}.")
                return
            
            self.process_list.clearSelection()
            items_to_select = []
            
            for pid in found_pids:
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    process_info.append(f"- PID: {pid}, Name: {name}")
                    
                    for i in range(self.process_list.count()):
                        item = self.process_list.item(i)
                        if item and item.data(Qt.UserRole) == pid:
                            items_to_select.append(item)
                            break
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_info.append(f"- PID: {pid}, Name: (N/A)")
            
            for item in items_to_select:
                item.setSelected(True)
                self.process_list.scrollToItem(item, QAbstractItemView.PositionAtCenter)
            
            QMessageBox.information(self, "Process Found", f"Found process(es) for port {port}:\n\n" + "\n".join(process_info))
        
        except psutil.AccessDenied:
            QMessageBox.critical(self, "Access Denied", "Cannot retrieve network info. Try admin/root.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error finding process by port: {e}")

    # --- Notepad Methods ---
    def on_notepad_tab_changed(self, index):
        self.save_current_note_if_changed()
    
    def on_notepad_text_changed(self):
        index = self.notepad_tabs.currentIndex()
        if index != -1:
            self.notes_changed[index] = True
            self.mark_tab_unsaved(index, True)
            self.note_save_timer.start()
    
    def mark_tab_unsaved(self, index, unsaved):
        try:
            tab_bar = self.notepad_tabs.tabBar()
            tab_text = self.notepad_tabs.tabText(index)
            tab_bar.setTabData(index, unsaved) # Store state
            
            if unsaved:
                if not tab_text.endswith(" *"):
                    self.notepad_tabs.setTabText(index, tab_text + " *")
            else:
                if tab_text.endswith(" *"):
                    self.notepad_tabs.setTabText(index, tab_text[:-2])
            
            style = tab_bar.style()
            style.unpolish(tab_bar)
            style.polish(tab_bar) # Refresh style
        
        except Exception as e:
            logging.error(f"Error marking tab unsaved: {e}")
    
    def save_current_note_if_changed(self):
        for index, changed in list(self.notes_changed.items()):
            if changed and index != self.notepad_tabs.currentIndex():
                self.save_note(index, mark_saved=True)
    
    def save_all_notes(self):
        logging.info("Saving all unsaved notes...")
        saved_count = 0
        
        for index in range(self.notepad_tabs.count()):
            if self.notes_changed.get(index, False):
                if self.save_note(index, mark_saved=True):
                    saved_count += 1
        
        logging.info(f"Saved {saved_count} notes.")
    
    def save_note(self, index, mark_saved=True):
        if not (0 <= index < self.notepad_tabs.count()):
            return False
        
        widget = self.notepad_tabs.widget(index)
        tab_name = self.notepad_tabs.tabText(index)
        
        if tab_name.endswith(" *"):
            tab_name = tab_name[:-2]
        
        if isinstance(widget, QTextEdit):
            filepath = self.get_note_filepath(tab_name)
            content = widget.toPlainText()
            timestamp = time.time()
            
            try:
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)
                
                widget.setProperty("timestamp", timestamp)
                
                if mark_saved:
                    self.notes_changed[index] = False
                    self.mark_tab_unsaved(index, False)
                
                logging.info(f"Saved note '{tab_name}' to {filepath}")
                self.schedule_sync("notepad_update", {"name": tab_name, "content": content, "timestamp": timestamp})
                
                return True
            
            except Exception as e:
                QMessageBox.warning(self, "Save Error", f"Failed to save note '{tab_name}':\n{e}")
                return False
        
        return False
    
    def get_note_filepath(self, note_name):
        safe_filename = re.sub(r"[\/*?:\"<>|]", "_", note_name) + ".txt"
        return os.path.join(self.notes_directory, safe_filename)
    
    def load_notes(self):
        logging.info(f"Loading notes from: {self.notes_directory}")
        
        try:
            while self.notepad_tabs.count() > 0:
                self.notepad_tabs.removeTab(0)
            
            self.notes_changed.clear()
            
            if not os.path.isdir(self.notes_directory):
                return self.add_initial_notepad_tab()
            
            loaded_count = 0
            
            for filename in sorted(os.listdir(self.notes_directory)):
                if filename.endswith(".txt"):
                    filepath = os.path.join(self.notes_directory, filename)
                    tab_name = os.path.splitext(filename)[0]
                    
                    try:
                        with open(filepath, "r", encoding="utf-8") as f:
                            content = f.read()
                        
                        timestamp = os.path.getmtime(filepath)
                        self.add_new_notepad_tab(name=tab_name, content=content, timestamp=timestamp)
                        loaded_count += 1
                    
                    except Exception as e:
                        logging.error(f"Error loading note '{filename}': {e}")
            
            if loaded_count == 0:
                self.add_initial_notepad_tab()
            
            logging.info(f"Loaded {loaded_count} notes.")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load notes: {e}")
            self.add_initial_notepad_tab()
    
    def add_initial_notepad_tab(self):
        if self.notepad_tabs.count() == 0:
            self.add_new_notepad_tab(name="Note 1", content="")
    
    def add_new_notepad_tab(self, name=None, content="", timestamp=None):
        try:
            if name is None:
                i = 1
                while True:
                    potential_name = f"New Note {i}"
                    if not os.path.exists(self.get_note_filepath(potential_name)):
                        name = potential_name
                        break
                    i += 1
                    if i > 1000:
                        name = f"Untitled_{int(time.time())}"
                        break
            
            text_edit = QTextEdit()
            text_edit.setPlainText(content)
            text_edit.setProperty("timestamp", timestamp or time.time())
            
            index = self.notepad_tabs.addTab(text_edit, name)
            self.notepad_tabs.setCurrentIndex(index)
            self.notes_changed[index] = False
            text_edit.textChanged.connect(self.on_notepad_text_changed)
            self.mark_tab_unsaved(index, False)
        
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to add new note tab: {e}")
    
    def rename_current_notepad_tab(self):
        idx = self.notepad_tabs.currentIndex()
        old_name_display = self.notepad_tabs.tabText(idx)
        
        if idx == -1:
            return
        
        was_unsaved = old_name_display.endswith(" *")
        old_name_actual = old_name_display[:-2] if was_unsaved else old_name_display
        old_filepath = self.get_note_filepath(old_name_actual)
        
        new_name_actual, ok = QInputDialog.getText(self, "Rename Note", "New name:", QLineEdit.Normal, old_name_actual)
        
        if ok and new_name_actual and new_name_actual != old_name_actual:
            new_filepath = self.get_note_filepath(new_name_actual)
            
            if os.path.exists(new_filepath):
                QMessageBox.warning(self, "Rename Failed", f"Note '{new_name_actual}' already exists.")
                return
            
            try:
                current_widget = self.notepad_tabs.widget(idx)
                
                if isinstance(current_widget, QTextEdit):
                    content_to_save = current_widget.toPlainText()
                    os.makedirs(os.path.dirname(new_filepath), exist_ok=True)
                    
                    with open(new_filepath, "w", encoding="utf-8") as f:
                        f.write(content_to_save)
                    
                    if os.path.exists(old_filepath) and old_filepath != new_filepath:
                        os.remove(old_filepath)
                    
                    new_name_display = new_name_actual + (" *" if was_unsaved else "")
                    self.notepad_tabs.setTabText(idx, new_name_display)
                    self.notes_changed[idx] = False
                    self.mark_tab_unsaved(idx, False)
                    self.schedule_sync("notepad_rename", {"old_name": old_name_actual, "new_name": new_name_actual})
            
            except Exception as e:
                QMessageBox.warning(self, "Rename Error", f"Failed to rename note: {e}")
                self.notepad_tabs.setTabText(idx, old_name_display) # Revert
    
    def close_notepad_tab(self, index):
        if not (0 <= index < self.notepad_tabs.count()):
            return
        
        tab_name_display = self.notepad_tabs.tabText(index)
        tab_name_actual = tab_name_display[:-2] if tab_name_display.endswith(" *") else tab_name_display
        is_unsaved = self.notes_changed.get(index, False)
        
        if is_unsaved:
            reply = QMessageBox.question(self, "Unsaved Changes", f"Save '{tab_name_actual}'?", QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel)
            
            if reply == QMessageBox.Cancel:
                return
            elif reply == QMessageBox.Save and not self.save_note(index, mark_saved=True):
                return
        
        try:
            self.notepad_tabs.removeTab(index)
            
            if index in self.notes_changed:
                del self.notes_changed[index]
            
            # Re-index notes_changed
            new_notes_changed = {}
            for old_idx, status in self.notes_changed.items():
                if old_idx > index:
                    new_notes_changed[old_idx - 1] = status
                elif old_idx < index:
                    new_notes_changed[old_idx] = status
            
            self.notes_changed = new_notes_changed
            self.schedule_sync("notepad_delete", {"name": tab_name_actual})
            
            if self.notepad_tabs.count() == 0:
                self.add_initial_notepad_tab()
        
        except Exception as e:
            logging.error(f"Error closing notepad tab {index}: {e}")
    
    def show_notepad_tab_context_menu(self, position):
        try:
            tab_bar = self.notepad_tabs.tabBar()
            index = tab_bar.tabAt(position)
            
            if index != -1:
                menu = QMenu()
                rename_action = menu.addAction("Rename")
                close_action = menu.addAction("Close")
                
                action = menu.exec(tab_bar.mapToGlobal(position))
                
                if action == rename_action:
                    self.rename_current_notepad_tab()
                elif action == close_action:
                    self.close_notepad_tab(index)
        
        except Exception as e:
            logging.error(f"Error in notepad context menu: {e}")

    # --- P2P Sync Logic ---
    def schedule_sync(self, data_type, details=None):
        self.needs_sync = True
        logging.debug(f"Sync scheduled for {data_type}. Details: {details}")

    def trigger_sync(self):
        if not self.p2p_manager or not self.p2p_manager.p2p_enabled or not self.p2p_manager.running:
            logging.debug("P2P Sync: Triggered but P2P manager not active or enabled.")
            return
        
        logging.info("Triggering P2P data sync...")
        
        try:
            clipboard_data = [item.to_dict() for item in self.clipboard_history if item.to_dict() is not None]
            notepad_data = {}
            
            for i in range(self.notepad_tabs.count()):
                widget = self.notepad_tabs.widget(i)
                tab_name_display = self.notepad_tabs.tabText(i)
                tab_name_actual = tab_name_display[:-2] if tab_name_display.endswith(" *") else tab_name_display
                
                if isinstance(widget, QTextEdit):
                    timestamp = widget.property("timestamp") or time.time()
                    notepad_data[tab_name_actual] = {"content": widget.toPlainText(), "timestamp": timestamp}
            
            sync_payload = {
                "type": "SYNC_DATA",
                "clipboard": clipboard_data,
                "notepad": notepad_data,
                "sender_timestamp": time.time()
            }
            
            self.send_p2p_data_signal.emit(sync_payload)
            self.log_status("Sync data prepared for P2P manager.", 3000)
            self.needs_sync = False
        
        except Exception as e:
            logging.error(f"Error preparing or triggering P2P sync: {e}", exc_info=True)
            self.log_status(f"P2P Sync Error: {e}", 5000)

    @Slot(dict)
    def handle_received_p2p_data(self, data):
        if not self.p2p_manager or not self.p2p_manager.p2p_enabled:
            logging.debug("P2P Data: Received but P2P manager not active or enabled.")
            return
        
        data_type = data.get("type")
        logging.info(f"Handling received P2P data of type: {data_type}")
        
        try:
            if data_type == "SYNC_DATA":
                remote_clipboard = data.get("clipboard", [])
                self.sync_clipboard_history(remote_clipboard)
                
                remote_notepad = data.get("notepad", {})
                self.sync_notepad_content(remote_notepad)
                
                self.log_status("P2P Sync data received and processed.", 3000)
            
            elif data_type == "NOTEPAD_RENAME":
                old_name = data.get("old_name")
                new_name = data.get("new_name")
                
                if old_name and new_name:
                    self.handle_remote_notepad_rename(old_name, new_name)
            
            elif data_type == "NOTEPAD_DELETE":
                 name_to_delete = data.get("name")
                 
                 if name_to_delete:
                     self.handle_remote_notepad_delete(name_to_delete)
        
        except Exception as e:
            logging.error(f"Error handling received P2P data: {e}", exc_info=True)
            self.log_status(f"P2P Sync Process Error: {e}", 5000)

    def sync_clipboard_history(self, remote_history_dicts):
        logging.debug(f"Syncing clipboard. Remote items: {len(remote_history_dicts)}, Local items: {len(self.clipboard_history)}")
        
        local_item_timestamps = {item.timestamp: item for item in self.clipboard_history}
        new_items_added = False
        
        for item_dict in remote_history_dicts:
            remote_item = ClipboardItem.from_dict(item_dict)
            
            if remote_item:
                if remote_item.timestamp not in local_item_timestamps:
                    self.clipboard_history.append(remote_item)
                    new_items_added = True
                    logging.debug(f"Added remote clipboard item (ts: {remote_item.timestamp})")
            else:
                logging.warning("Failed to create ClipboardItem from remote dict during sync.")
        
        if new_items_added:
            self.clipboard_history.sort(key=lambda x: x.timestamp, reverse=True)
            
            if len(self.clipboard_history) > MAX_CLIPBOARD_HISTORY:
                self.clipboard_history = self.clipboard_history[:MAX_CLIPBOARD_HISTORY]
            
            logging.info("Clipboard history updated from P2P sync.")
            self.update_clipboard_list_ui()

    def sync_notepad_content(self, remote_notepad_data):
        logging.debug(f"Syncing notepad. Remote notes: {len(remote_notepad_data)}")
        
        local_tabs_info = {}
        for i in range(self.notepad_tabs.count()):
            tab_name_display = self.notepad_tabs.tabText(i)
            tab_name_actual = tab_name_display[:-2] if tab_name_display.endswith(" *") else tab_name_display
            widget = self.notepad_tabs.widget(i)
            
            if isinstance(widget, QTextEdit):
                local_tabs_info[tab_name_actual] = {
                    "widget": widget, 
                    "index": i, 
                    "timestamp": widget.property("timestamp") or 0,
                    "is_unsaved": self.notes_changed.get(i, False)
                }

        current_tab_text_before_sync = self.notepad_tabs.tabText(self.notepad_tabs.currentIndex()) if self.notepad_tabs.count() > 0 else None
        ui_changed = False

        # Process updates and additions from remote
        for remote_name, remote_note_data in remote_notepad_data.items():
            remote_content = remote_note_data.get("content", "")
            remote_timestamp = remote_note_data.get("timestamp", 0)

            if remote_name in local_tabs_info:
                local_info = local_tabs_info[remote_name]
                local_widget = local_info["widget"]
                local_timestamp = local_info["timestamp"]
                local_is_unsaved = local_info["is_unsaved"]
                local_index = local_info["index"]

                if remote_timestamp > local_timestamp:
                    if local_is_unsaved and local_timestamp > remote_timestamp:
                        logging.info(f"Note '{remote_name}': Local unsaved version is newer, keeping local.")
                    elif local_widget.toPlainText() != remote_content:
                        logging.info(f"Note '{remote_name}': Updating with newer remote content (RemoteTS: {remote_timestamp}, LocalTS: {local_timestamp}).")
                        local_widget.setPlainText(remote_content)
                        local_widget.setProperty("timestamp", remote_timestamp)
                        self.notes_changed[local_index] = False
                        self.mark_tab_unsaved(local_index, False)
                        ui_changed = True
                elif local_timestamp > remote_timestamp and not local_is_unsaved:
                    logging.debug(f"Note '{remote_name}': Local saved version is newer. Remote will update.")

            else:
                logging.info(f"Note '{remote_name}': Adding new note from remote sync.")
                self.add_new_notepad_tab(name=remote_name, content=remote_content, timestamp=remote_timestamp)
                ui_changed = True
        
        # Process deletions
        local_note_names = set(local_tabs_info.keys())
        remote_note_names = set(remote_notepad_data.keys())
        notes_to_delete_locally = local_note_names - remote_note_names

        if notes_to_delete_locally:
            for note_name_to_delete in notes_to_delete_locally:
                logging.info(f"Note '{note_name_to_delete}': Removing as it was deleted remotely.")
                local_info = local_tabs_info[note_name_to_delete]
                
                self.notepad_tabs.removeTab(local_info["index"])
                
                if local_info["index"] in self.notes_changed:
                    del self.notes_changed[local_info["index"]]
                
                ui_changed = True

        if ui_changed:
            logging.info("Notepad content updated from P2P sync.")
            
            if self.notepad_tabs.count() == 0:
                self.add_initial_notepad_tab()
            
            # 현재 탭 복원
            if current_tab_text_before_sync:
                restored_idx = -1
                clean_current_tab_name = current_tab_text_before_sync[:-2] if current_tab_text_before_sync.endswith(" *") else current_tab_text_before_sync
                
                for i in range(self.notepad_tabs.count()):
                    tab_text = self.notepad_tabs.tabText(i)
                    clean_tab_text = tab_text[:-2] if tab_text.endswith(" *") else tab_text
                    
                    if clean_tab_text == clean_current_tab_name:
                        restored_idx = i
                        break
                
                if restored_idx != -1:
                    self.notepad_tabs.setCurrentIndex(restored_idx)

    def handle_remote_notepad_rename(self, old_name, new_name):
        logging.info(f"P2P Rename: Handling remote rename from '{old_name}' to '{new_name}'.")
        
        found_index = -1
        for i in range(self.notepad_tabs.count()):
            tab_name_display = self.notepad_tabs.tabText(i)
            tab_name_actual = tab_name_display[:-2] if tab_name_display.endswith(" *") else tab_name_display
            
            if tab_name_actual == old_name:
                found_index = i
                break
        
        if found_index != -1:
            # 새 이름이 이미 존재하는지 확인
            new_name_exists_elsewhere = any(
                (self.notepad_tabs.tabText(j)[:-2] if self.notepad_tabs.tabText(j).endswith(" *") else self.notepad_tabs.tabText(j)) == new_name 
                for j in range(self.notepad_tabs.count()) if j != found_index
            )
            
            if new_name_exists_elsewhere:
                logging.warning(f"P2P Rename: Cannot apply remote rename. Target name '{new_name}' already exists locally.")
                return
            
            was_unsaved = self.notepad_tabs.tabText(found_index).endswith(" *")
            new_display_name = new_name + (" *" if was_unsaved else "")
            self.notepad_tabs.setTabText(found_index, new_display_name)
            
            old_filepath = self.get_note_filepath(old_name)
            new_filepath = self.get_note_filepath(new_name)
            
            try:
                if os.path.exists(old_filepath):
                    os.rename(old_filepath, new_filepath)
                    logging.info(f"P2P Rename: Renamed note file '{old_filepath}' to '{new_filepath}'.")
                else:
                    widget = self.notepad_tabs.widget(found_index)
                    if isinstance(widget, QTextEdit):
                        with open(new_filepath, "w", encoding="utf-8") as f:
                            f.write(widget.toPlainText())
            except Exception as e:
                logging.error(f"P2P Rename: Error renaming note file: {e}")
        else:
            logging.warning(f"P2P Rename: Note '{old_name}' not found locally for remote rename.")

    def handle_remote_notepad_delete(self, name_to_delete):
        logging.info(f"P2P Delete: Handling remote delete for note: '{name_to_delete}'.")
        
        found_index = -1
        for i in range(self.notepad_tabs.count()):
            tab_name_display = self.notepad_tabs.tabText(i)
            tab_name_actual = tab_name_display[:-2] if tab_name_display.endswith(" *") else tab_name_display
            
            if tab_name_actual == name_to_delete:
                found_index = i
                break
        
        if found_index != -1:
            self.notepad_tabs.removeTab(found_index)
            
            if found_index in self.notes_changed:
                del self.notes_changed[found_index]
            
            # notes_changed 재인덱싱
            new_notes_changed = {}
            for old_idx, status in self.notes_changed.items():
                if old_idx > found_index:
                    new_notes_changed[old_idx - 1] = status
                elif old_idx < found_index:
                    new_notes_changed[old_idx] = status
            
            self.notes_changed = new_notes_changed
            logging.info(f"P2P Delete: Removed local note tab '{name_to_delete}'.")
            
            filepath = self.get_note_filepath(name_to_delete)
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                    logging.info(f"P2P Delete: Deleted local file: {filepath}")
                except Exception as e:
                    logging.error(f"P2P Delete: Failed to delete local file {filepath}: {e}")
            
            if self.notepad_tabs.count() == 0:
                self.add_initial_notepad_tab()
        else:
            logging.warning(f"P2P Delete: Note '{name_to_delete}' not found locally for remote delete.")

    @Slot(str, int)
    def log_status(self, message, timeout=0):
        try:
            self.status_bar.showMessage(message, timeout)
            logging.debug(f"Status Bar: {message}")
        except Exception as e:
            logging.error(f"Error showing status message: {e}")

    @Slot(str, int, str)
    def update_peer_status_ui(self, address, port, status):
        logging.info(f"Peer Status Update: {address}:{port} -> {status}")
        self.log_status(f"Peer {address}:{port} is now {status}", 3000)

    # --- Auto Hide Methods ---
    @Slot(bool, bool)
    def toggle_auto_hide(self, checked, save_setting=True):
        self.auto_hide_enabled = checked
        
        if save_setting:
            self.settings.setValue("window/autoHide", checked)
        
        if checked:
            if not self.auto_hide_timer.isActive():
                self.auto_hide_timer.start()
            
            self.check_mouse_position_for_auto_hide()
        else:
            if self.auto_hide_timer.isActive():
                self.auto_hide_timer.stop()
            
            if not self.isVisible():
                self.show_window()
        
        logging.info(f"Auto Hide toggled: {self.auto_hide_enabled}")

    @Slot()
    def check_mouse_position_for_auto_hide(self):
        if not self.auto_hide_enabled:
            return

        try:
            screen = QGuiApplication.primaryScreen()
            if not screen:
                return
            
            screen_geo = screen.availableGeometry()
            mouse_pos = QCursor.pos()

            edge_threshold = 10
            is_near_right_edge = mouse_pos.x() >= (screen_geo.right() - edge_threshold) and \
                                 screen_geo.top() <= mouse_pos.y() <= screen_geo.bottom()

            if is_near_right_edge:
                if not self.isVisible():
                    logging.debug("Mouse near right edge, showing sidebar.")
                    self.show_window()
                    self.activateWindow()
            else:
                if self.isVisible() and not self.is_mouse_over_window and not self.isActiveWindow():
                    logging.debug("Mouse not near edge, not over window, window inactive -> hiding sidebar.")
                    self.hide_window()

        except Exception as e:
            logging.warning(f"Could not check mouse position for auto-hide: {e}", exc_info=True)

    def mouseMoveEvent(self, event):
        super().mouseMoveEvent(event)
        screen = QApplication.primaryScreen()
        screen_geometry = screen.geometry()
        mouse_pos = QCursor.pos()
        
        # 마우스가 화면 우측 끝에 있는지 확인 (예: 10픽셀 이내)
        is_at_right_edge = abs(mouse_pos.x() - screen_geometry.right()) <= 10
        
        # 현재 윈도우의 위치가 우측에 있는지 확인
        window_pos = self.pos()
        is_window_at_right = abs(window_pos.x() - (screen_geometry.right() - self.width())) <= 10
        
        # 마우스가 우측 끝에 있고 윈도우도 우측에 있을 때만 최상위로 표시
        if is_at_right_edge and is_window_at_right:
            if not bool(self.windowFlags() & Qt.WindowStaysOnTopHint):
                self.setWindowFlags(self.windowFlags() | Qt.WindowStaysOnTopHint)
                self.show()
                self.raise_()
        else:
            if bool(self.windowFlags() & Qt.WindowStaysOnTopHint):
                self.setWindowFlags(self.windowFlags() & ~Qt.WindowStaysOnTopHint)
                self.show()
                self.raise_()

    def create_notepad_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # 노트 도구 모음
        tools_layout = QHBoxLayout()
        
        add_tab_button = QPushButton("+")
        add_tab_button.setToolTip("Add New Note")
        add_tab_button.setFixedSize(40, 25)
        add_tab_button.clicked.connect(lambda: self.add_new_notepad_tab())
        
        save_button = QPushButton("Save")
        save_button.setToolTip("Save current note")
        save_button.clicked.connect(self.save_current_note)
        
        load_button = QPushButton("Load")
        load_button.setToolTip("Load note from file")
        load_button.clicked.connect(self.load_note_from_file)
        
        sync_button = QPushButton("Sync")
        sync_button.setToolTip("Force sync notes")
        sync_button.clicked.connect(self.force_sync_notes)
        
        tools_layout.addWidget(add_tab_button)
        tools_layout.addWidget(save_button)
        tools_layout.addWidget(load_button)
        tools_layout.addWidget(sync_button)
        tools_layout.addStretch()
        
        layout.addLayout(tools_layout)
        
        self.notepad_tabs = QTabWidget()
        self.notepad_tabs.setTabsClosable(True)
        self.notepad_tabs.setMovable(True)
        self.notepad_tabs.tabCloseRequested.connect(self.close_notepad_tab)
        self.notepad_tabs.currentChanged.connect(self.on_notepad_tab_changed)
        self.notepad_tabs.tabBar().setContextMenuPolicy(Qt.CustomContextMenu)
        self.notepad_tabs.tabBar().customContextMenuRequested.connect(self.show_notepad_tab_context_menu)
        
        layout.addWidget(self.notepad_tabs)
        
        return widget

    def add_new_notepad_tab(self, name=None, content="", timestamp=None):
        try:
            if name is None:
                i = 1
                while True:
                    potential_name = f"New Note {i}"
                    if not os.path.exists(self.get_note_filepath(potential_name)):
                        name = potential_name
                        break
                    i += 1
                    if i > 1000:
                        name = f"Untitled_{int(time.time())}"
                        break
            
            # QTextEdit 대신 MarkdownEditor 사용
            editor = MarkdownEditor()
            editor.setPlainText(content)
            editor.setProperty("timestamp", timestamp or time.time())
            
            index = self.notepad_tabs.addTab(editor, name)
            self.notepad_tabs.setCurrentIndex(index)
            self.notes_changed[index] = False
            
            # Signal 연결
            editor.text_changed_signal.connect(self.on_notepad_text_changed)
            self.mark_tab_unsaved(index, False)
            
            return index
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to add new note tab: {e}")
            return -1

    def on_notepad_text_changed(self):
        index = self.notepad_tabs.currentIndex()
        if index != -1:
            self.notes_changed[index] = True
            self.mark_tab_unsaved(index, True)
            self.note_save_timer.start()

    def save_note(self, index, mark_saved=True):
        if not (0 <= index < self.notepad_tabs.count()):
            return False
        
        widget = self.notepad_tabs.widget(index)
        tab_name = self.notepad_tabs.tabText(index)
        
        if tab_name.endswith(" *"):
            tab_name = tab_name[:-2]
        
        if isinstance(widget, MarkdownEditor):  # QTextEdit 대신 MarkdownEditor 검사
            filepath = self.get_note_filepath(tab_name)
            content = widget.toPlainText()  # 메서드 이름은 동일
            timestamp = time.time()
            
            try:
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)
                
                widget.setProperty("timestamp", timestamp)
                
                if mark_saved:
                    self.notes_changed[index] = False
                    self.mark_tab_unsaved(index, False)
                
                logging.info(f"Saved note '{tab_name}' to {filepath}")
                self.schedule_sync("notepad_update", {"name": tab_name, "content": content, "timestamp": timestamp})
                
                return True
            
            except Exception as e:
                QMessageBox.warning(self, "Save Error", f"Failed to save note '{tab_name}':\n{e}")
                return False
        
        return False

    def save_current_note(self):
        index = self.notepad_tabs.currentIndex()
        if index != -1:
            if self.save_note(index, mark_saved=True):
                self.log_status(f"Note '{self.notepad_tabs.tabText(index)}' saved successfully.", 3000)

    def load_note_from_file(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Load Note", "", "Markdown Files (*.md);;Text Files (*.txt);;All Files (*)"
        )
        
        if not filepath:
            return
        
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            
            filename = os.path.basename(filepath)
            name, _ = os.path.splitext(filename)
            
            # 이미 같은 이름의 탭이 있는지 확인
            for i in range(self.notepad_tabs.count()):
                tab_text = self.notepad_tabs.tabText(i)
                if tab_text.endswith(" *"):
                    tab_text = tab_text[:-2]
                
                if tab_text == name:
                    reply = QMessageBox.question(
                        self, "Note Exists", 
                        f"A note named '{name}' already exists. Do you want to replace it?",
                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                    )
                    
                    if reply == QMessageBox.Yes:
                        widget = self.notepad_tabs.widget(i)
                        if isinstance(widget, MarkdownEditor):
                            widget.setPlainText(content)
                            self.notepad_tabs.setCurrentIndex(i)
                            self.notes_changed[i] = True
                            self.mark_tab_unsaved(i, True)
                            self.log_status(f"Note '{name}' replaced with content from {filepath}", 3000)
                            return
                    else:
                        # 다른 이름으로 추가
                        name = f"{name}_imported"
            
            # 새 탭 추가
            index = self.add_new_notepad_tab(name=name, content=content)
            if index >= 0:
                self.log_status(f"Note loaded from {filepath}", 3000)
        
        except Exception as e:
            QMessageBox.warning(self, "Load Error", f"Failed to load note from '{filepath}':\n{e}")

    def force_sync_notes(self):
        if not self.p2p_manager or not self.p2p_manager.p2p_enabled or not self.p2p_manager.running:
            QMessageBox.information(self, "Sync Info", "P2P synchronization is not enabled or not running.")
            return
        
        # 모든 노트 먼저 저장
        self.save_all_notes()
        
        # 동기화 준비 및 트리거
        self.log_status("Forcing notes synchronization...", 3000)
        self.trigger_sync()
        
        QMessageBox.information(self, "Sync", "Notes synchronization has been triggered.")

    def sync_notepad_content(self, remote_notepad_data):
        logging.debug(f"Syncing notepad. Remote notes: {len(remote_notepad_data)}")
        
        local_tabs_info = {}
        for i in range(self.notepad_tabs.count()):
            tab_name_display = self.notepad_tabs.tabText(i)
            tab_name_actual = tab_name_display[:-2] if tab_name_display.endswith(" *") else tab_name_display
            widget = self.notepad_tabs.widget(i)
            
            if isinstance(widget, MarkdownEditor):  # QTextEdit 대신 MarkdownEditor 검사
                local_tabs_info[tab_name_actual] = {
                    "widget": widget, 
                    "index": i, 
                    "timestamp": widget.property("timestamp") or 0,
                    "is_unsaved": self.notes_changed.get(i, False)
                }

        current_tab_text_before_sync = self.notepad_tabs.tabText(self.notepad_tabs.currentIndex()) if self.notepad_tabs.count() > 0 else None
        ui_changed = False

        # Process updates and additions from remote
        for remote_name, remote_note_data in remote_notepad_data.items():
            remote_content = remote_note_data.get("content", "")
            remote_timestamp = remote_note_data.get("timestamp", 0)

            if remote_name in local_tabs_info:
                local_info = local_tabs_info[remote_name]
                local_widget = local_info["widget"]
                local_timestamp = local_info["timestamp"]
                local_is_unsaved = local_info["is_unsaved"]
                local_index = local_info["index"]

                if remote_timestamp > local_timestamp:
                    if local_is_unsaved and local_timestamp > remote_timestamp:
                        logging.info(f"Note '{remote_name}': Local unsaved version is newer, keeping local.")
                    elif local_widget.toPlainText() != remote_content:
                        logging.info(f"Note '{remote_name}': Updating with newer remote content (RemoteTS: {remote_timestamp}, LocalTS: {local_timestamp}).")
                        local_widget.setPlainText(remote_content)
                        local_widget.setProperty("timestamp", remote_timestamp)
                        self.notes_changed[local_index] = False
                        self.mark_tab_unsaved(local_index, False)
                        ui_changed = True
                elif local_timestamp > remote_timestamp and not local_is_unsaved:
                    logging.debug(f"Note '{remote_name}': Local saved version is newer. Remote will update.")

            else:
                logging.info(f"Note '{remote_name}': Adding new note from remote sync.")
                self.add_new_notepad_tab(name=remote_name, content=remote_content, timestamp=remote_timestamp)
                ui_changed = True
        
        # Process deletions
        local_note_names = set(local_tabs_info.keys())
        remote_note_names = set(remote_notepad_data.keys())
        notes_to_delete_locally = local_note_names - remote_note_names

        if notes_to_delete_locally:
            for note_name_to_delete in notes_to_delete_locally:
                logging.info(f"Note '{note_name_to_delete}': Removing as it was deleted remotely.")
                local_info = local_tabs_info[note_name_to_delete]
                
                self.notepad_tabs.removeTab(local_info["index"])
                
                if local_info["index"] in self.notes_changed:
                    del self.notes_changed[local_info["index"]]
                
                ui_changed = True

        if ui_changed:
            logging.info("Notepad content updated from P2P sync.")
            
            if self.notepad_tabs.count() == 0:
                self.add_initial_notepad_tab()
            
            # 현재 탭 복원
            if current_tab_text_before_sync:
                restored_idx = -1
                clean_current_tab_name = current_tab_text_before_sync[:-2] if current_tab_text_before_sync.endswith(" *") else current_tab_text_before_sync
                
                for i in range(self.notepad_tabs.count()):
                    tab_text = self.notepad_tabs.tabText(i)
                    clean_tab_text = tab_text[:-2] if tab_text.endswith(" *") else tab_text
                    
                    if clean_tab_text == clean_current_tab_name:
                        restored_idx = i
                        break
                
                if restored_idx != -1:
                    self.notepad_tabs.setCurrentIndex(restored_idx)

    def load_notes(self):
        logging.info(f"Loading notes from: {self.notes_directory}")
        
        try:
            while self.notepad_tabs.count() > 0:
                self.notepad_tabs.removeTab(0)
            
            self.notes_changed.clear()
            
            if not os.path.isdir(self.notes_directory):
                return self.add_initial_notepad_tab()
            
            loaded_count = 0
            
            for filename in sorted(os.listdir(self.notes_directory)):
                if filename.endswith(".txt") or filename.endswith(".md"):
                    filepath = os.path.join(self.notes_directory, filename)
                    tab_name = os.path.splitext(filename)[0]
                    
                    try:
                        with open(filepath, "r", encoding="utf-8") as f:
                            content = f.read()
                        
                        timestamp = os.path.getmtime(filepath)
                        self.add_new_notepad_tab(name=tab_name, content=content, timestamp=timestamp)
                        loaded_count += 1
                    
                    except Exception as e:
                        logging.error(f"Error loading note '{filename}': {e}")
            
            if loaded_count == 0:
                self.add_initial_notepad_tab()
            
            logging.info(f"Loaded {loaded_count} notes.")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load notes: {e}")
            self.add_initial_notepad_tab()

    def get_note_filepath(self, note_name):
        # .txt 대신 .md 확장자 사용
        safe_filename = re.sub(r"[\/*?:\"<>|]", "_", note_name) + ".md"
        return os.path.join(self.notes_directory, safe_filename)

# --- Main Execution ---
if __name__ == "__main__":
    try:
        app_data_path = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation)
        if not os.path.exists(app_data_path):
            os.makedirs(app_data_path, exist_ok=True)
    except Exception as e:
        logging.critical(f"Failed to create AppData directory: {e}")

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    # 마지막 창이 닫혀도 앱이 종료되지 않도록 설정 (트레이 기능용)
    app.setQuitOnLastWindowClosed(False)

    try:
        window = MainWindow()
        logging.info("Application starting...")
        exit_code = app.exec()
        logging.info(f"Application exited with code {exit_code}.")
        sys.exit(exit_code)
    except Exception as e:
        logging.critical(f"Unhandled exception in main execution: {e}", exc_info=True)
        try:
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Critical)
            msg_box.setWindowTitle("Fatal Error")
            msg_box.setText(f"An unhandled error occurred and the application must close.\n\n{e}\n\nSee log file for details.")
            msg_box.exec()
        except:
            pass
        sys.exit(1)