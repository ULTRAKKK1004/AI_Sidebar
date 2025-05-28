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
    QToolButton, QSizePolicy, QTextBrowser, QFrame
)
from PySide6.QtCore import (
    Qt, QTimer, QSettings, QSize, QMimeData, QDir, QStandardPaths, QRect,
    QByteArray, QBuffer, QIODevice, Signal, QObject, QThread, Slot, QEvent,
    QMetaObject, Q_ARG, QPoint, QUrl, QPropertyAnimation, QEasingCurve
)
from PySide6.QtGui import (
    QClipboard, QPixmap, QImage, QAction, QIcon, QGuiApplication, QCursor,
    QShortcut, QKeySequence, QScreen, QCloseEvent, QTextCursor, QPainter,
    QDrag, QDropEvent, QDragEnterEvent, QFont, QFontDatabase, QSyntaxHighlighter,
    QTextCharFormat, QColor, QPen
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
LOG_FILE_MAX_BYTES = 5 * 1024 * 1024  # 수정: 곱셈 연산자 사이 공백 제거
LOG_FILE_BACKUP_COUNT = 5
MAX_CONVERSATION_LENGTH = 2000
MAX_FILE_SIZE = 50 * 1024 * 1024  # 수정: 곱셈 연산자 사이 공백 제거
MAGNETIC_THRESHOLD = 20

# 전역 상수 정의
DEFAULT_WEBUI_ENDPOINT = os.getenv("DEFAULT_WEBUI_ENDPOINT", "https://chat.ai-personalserv.com")
DEFAULT_WEBUI_API_KEY = os.getenv("DEFAULT_WEBUI_API_KEY", "sk-8b155ef2e37244e299dd45cff5a88092")
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


# --- Markdown Highlighter Class ---
class MarkdownHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []
        
        # Headers
        header_format = QTextCharFormat()
        header_format.setFontWeight(QFont.Bold)
        header_format.setForeground(QColor("#0066CC"))
        self.highlighting_rules.append(("^#\\\\s+.+$", header_format))
        self.highlighting_rules.append(("^##\\\\s+.+$", header_format))
        self.highlighting_rules.append(("^###\\\\s+.+$", header_format))
        
        # Bold
        bold_format = QTextCharFormat()
        bold_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append(("\\\\*\\\\*[^\\\\*]+\\\\*\\\\*", bold_format))
        self.highlighting_rules.append(("__[^_]+__", bold_format))
        
        # Italic
        italic_format = QTextCharFormat()
        italic_format.setFontItalic(True)
        self.highlighting_rules.append(("\\\\*[^\\\\*]+\\\\*", italic_format))
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
        self.highlighting_rules.append(("\\\\[.+\\\\]\\\\(.+\\\\)", link_format))
        
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


# --- Enhanced Draggable Widget with Magnet Effect and Glow Animation ---
class DraggableWidget(QFrame):
    def __init__(self, title, content_widget, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.Box)
        self.setLineWidth(1)
        self.dragging = False
        self.drag_position = QPoint()
        self.glow_animation = None
        self.is_selected = False
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # 타이틀 바
        title_bar = QWidget()
        title_bar.setFixedHeight(30)
        title_bar.setStyleSheet("background-color: #e0e0e0; border-bottom: 1px solid #ccc;")
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(10, 5, 10, 5)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("font-weight: bold; border: none;")
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        
        layout.addWidget(title_bar)
        layout.addWidget(content_widget)
        
        # 타이틀 바에 드래그 기능 설정
        title_bar.mousePressEvent = self.mousePressEvent
        title_bar.mouseMoveEvent = self.mouseMoveEvent
        title_bar.mouseReleaseEvent = self.mouseReleaseEvent
        title_label.mousePressEvent = self.mousePressEvent
        title_label.mouseMoveEvent = self.mouseMoveEvent
        title_label.mouseReleaseEvent = self.mouseReleaseEvent
        
        self.setStyleSheet("""
            DraggableWidget {
                border: 2px solid #ccc;
                border-radius: 5px;
                background-color: white;
            }
            DraggableWidget:hover {
                border-color: #999;
            }
        """)
        
        # 자석 효과를 위한 설정
        self.magnetic_threshold = MAGNETIC_THRESHOLD  # 자석 효과 발동 거리
        self.snap_animation = None

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.dragging = True
            self.drag_position = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            self.start_glow_effect()
            event.accept()

    def mouseMoveEvent(self, event):
        if self.dragging and event.buttons() & Qt.LeftButton:
            new_pos = event.globalPosition().toPoint() - self.drag_position
            snapped_pos = self.apply_magnetic_effect(QPoint(new_pos))  # 복사본 전달
            if self.pos() != snapped_pos:
                self.move(snapped_pos)
            event.accept()
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        self.dragging = False
        self.stop_glow_effect()
        event.accept()

    def apply_magnetic_effect(self, pos):
        """다른 드래그 가능한 위젯들과의 자석 효과 (Y축만 snap, threshold 밖에서는 snap 없음)"""
        if not self.parent():
            return pos

        parent_widget = self.parent()
        my_rect = QRect(pos, self.size())
        min_dist_y = self.magnetic_threshold + 1
        snap_y = None

        for child in parent_widget.findChildren(DraggableWidget):
            if child == self:
                continue

            child_rect = child.geometry()

            for my_edge, child_edge, set_func in [
                (my_rect.top(), child_rect.top(), lambda v: child_rect.top()),
                (my_rect.bottom(), child_rect.bottom(), lambda v: child_rect.bottom() - my_rect.height()),
                (my_rect.top(), child_rect.bottom(), lambda v: child_rect.bottom()),
                (my_rect.bottom(), child_rect.top(), lambda v: child_rect.top() - my_rect.height()),
            ]:
                dist = abs(my_edge - child_edge)
                if dist < min_dist_y:
                    min_dist_y = dist
                    snap_y = set_func(my_edge)

        # threshold 이내일 때만 snap, threshold 밖이면 드래그한 위치 그대로
        if snap_y is not None and min_dist_y <= self.magnetic_threshold:
            pos.setY(snap_y)
        # threshold 밖이면 pos.y()는 사용자가 드래그한 위치(new_pos)를 유지
        return pos

    def start_glow_effect(self):
        """클릭된 객체 외각에 형광띠 애니메이션 효과"""
        self.is_selected = True
        
        # 기존 애니메이션 정리
        if self.glow_animation:
            self.glow_animation.stop()
            
        # 형광띠 효과를 위한 스타일 변경
        self.glow_animation = QPropertyAnimation(self, b"styleSheet")
        self.glow_animation.setDuration(1000)
        self.glow_animation.setLoopCount(-1)  # 무한 반복
        
        # 애니메이션 키프레임
        self.glow_animation.setKeyValueAt(0.0, """
            DraggableWidget {
                border: 3px solid #00aaff;
                border-radius: 5px;
                background-color: white;
            }
        """)
        self.glow_animation.setKeyValueAt(0.5, """
            DraggableWidget {
                border: 5px solid #66ddff;
                border-radius: 5px;
                background-color: white;
                box-shadow: 0 0 15px rgba(0, 170, 255, 0.7);
            }
        """)
        self.glow_animation.setKeyValueAt(1.0, """
            DraggableWidget {
                border: 3px solid #00aaff;
                border-radius: 5px;
                background-color: white;
            }
        """)
        
        self.glow_animation.setEasingCurve(QEasingCurve.InOutSine)
        self.glow_animation.start()

    def stop_glow_effect(self):
        """형광띠 효과 중지"""
        self.is_selected = False
        
        if self.glow_animation:
            self.glow_animation.stop()
            self.glow_animation = None
            
        # 원래 스타일로 복원
        self.setStyleSheet("""
            DraggableWidget {
                border: 2px solid #ccc;
                border-radius: 5px;
                background-color: white;
            }
            DraggableWidget:hover {
                border-color: #999;
            }
        """)
# --- Enhanced Clipboard Item Widget with Hide/Show functionality ---
class ClipboardItemWidget(QWidget):
    def __init__(self, clipboard_item, index, parent=None):
        super().__init__(parent)
        self.clipboard_item = clipboard_item
        self.index = index
        self.parent_widget = parent
        self.setup_ui()

    def setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # 콘텐츠 표시
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        
        if self.clipboard_item.data_type == "text":
            preview = self.clipboard_item.data.split("\n")[0][:50] + ("..." if len(self.clipboard_item.data) > 50 else "")
            content_label = QLabel(f"{self.index+1}. {preview}")
        elif self.clipboard_item.data_type == "image":
            content_label = QLabel(f"{self.index+1}. [Image]")
            # 이미지 아이콘 설정
            if isinstance(self.clipboard_item.data, QPixmap):
                icon_label = QLabel()
                icon_label.setPixmap(self.clipboard_item.data.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                content_layout.addWidget(icon_label)
        
        content_layout.addWidget(content_label)
        layout.addWidget(content_widget)
        
        # 버튼 영역 (수평 배치)
        button_layout = QHBoxLayout()
        button_layout.setSpacing(2)
        
        # 고정/고정해제 버튼
        self.pin_button = QPushButton("📌" if not self.clipboard_item.pinned else "📍")
        self.pin_button.setFixedSize(30, 25)
        self.pin_button.setToolTip("Pin/Unpin item")
        self.pin_button.clicked.connect(self.toggle_pin)
        
        # 삭제 버튼
        self.delete_button = QPushButton("🗑")
        self.delete_button.setFixedSize(30, 25)
        self.delete_button.setToolTip("Delete item")
        self.delete_button.clicked.connect(self.delete_item)
        self.delete_button.setEnabled(not self.clipboard_item.pinned)  # 고정된 아이템은 삭제 불가
        
        # 숨기기/보이기 버튼
        hide_icon = "👁‍🗨" if self.clipboard_item.hidden else "👁"
        self.hide_button = QPushButton(hide_icon)
        self.hide_button.setFixedSize(30, 25)
        self.hide_button.setToolTip("Hide/Show item")
        self.hide_button.clicked.connect(self.toggle_hide)
        
        button_layout.addWidget(self.pin_button)
        button_layout.addWidget(self.delete_button)
        button_layout.addWidget(self.hide_button)
        layout.addLayout(button_layout)
        
        # 상태에 따른 스타일 적용
        self.update_style()

    def update_style(self):
        """상태에 따라 스타일을 업데이트"""
        if self.clipboard_item.hidden:
            self.setStyleSheet("background-color: #f0f0f0; opacity: 0.5;")
        elif self.clipboard_item.pinned:
            self.setStyleSheet("background-color: #fff3cd;")
        else:
            self.setStyleSheet("")

    def toggle_pin(self):
        self.clipboard_item.pinned = not self.clipboard_item.pinned
        self.pin_button.setText("📍" if self.clipboard_item.pinned else "📌")
        self.delete_button.setEnabled(not self.clipboard_item.pinned)
        self.update_style()
        
        if hasattr(self.parent_widget, 'update_clipboard_list_ui'):
            self.parent_widget.update_clipboard_list_ui()

    def delete_item(self):
        if not self.clipboard_item.pinned:
            if hasattr(self.parent_widget, 'delete_clipboard_item'):
                self.parent_widget.delete_clipboard_item(self.index)

    def toggle_hide(self):
        """숨기기/보이기 토글 - 수정된 부분"""
        self.clipboard_item.hidden = not self.clipboard_item.hidden
        hide_icon = "👁‍🗨" if self.clipboard_item.hidden else "👁"
        self.hide_button.setText(hide_icon)
        self.hide_button.setToolTip("Show item" if self.clipboard_item.hidden else "Hide item")
        self.update_style()
        
        if hasattr(self.parent_widget, 'update_clipboard_list_ui'):
            self.parent_widget.update_clipboard_list_ui()
class EnhancedAssistantWidget(QTextBrowser):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setOpenExternalLinks(True)
        self.setStyleSheet("""
            QTextBrowser {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 10px;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                font-size: 14px;
                line-height: 1.5;
            }
            pre {
                background-color: #f4f4f4;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 10px;
                font-family: 'Courier New', Consolas, monospace;
                overflow-x: auto;
                position: relative;
            }
            code {
                background-color: #f4f4f4;
                border-radius: 3px;
                padding: 2px 4px;
                font-family: 'Courier New', Consolas, monospace;
                font-size: 90%;
            }
            blockquote {
                border-left: 4px solid #ddd;
                margin: 0;
                padding-left: 16px;
                color: #666;
            }
            .copy-button {
                position: absolute;
                top: 5px;
                right: 5px;
                background: #007bff;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 3px;
                cursor: pointer;
                font-size: 12px;
            }
            .copy-button:hover {
                background: #0056b3;
            }
        """)

    def append_markdown_text(self, markdown_text):
        # 마크다운을 HTML로 변환
        extensions = [
            'markdown.extensions.fenced_code',
            'markdown.extensions.tables',
            'markdown.extensions.nl2br',
            'markdown.extensions.codehilite',
            TocExtension(baselevel=1)
        ]
        try:
            html = markdown.markdown(markdown_text, extensions=extensions)
            # 코드 복사 버튼 추가
            html = self.add_copy_buttons_to_code_blocks(html)
            self.insertHtml(html)
        except Exception as e:
            logging.error(f"Error converting markdown to HTML: {e}")
            # fallback: 일반 텍스트로 추가
            self.insertPlainText(markdown_text)
        
        # 스크롤을 맨 아래로
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.setTextCursor(cursor)

    def add_copy_buttons_to_code_blocks(self, html):
        # 코드 블록에 복사 버튼 추가
        import re
        def add_copy_button(match):
            code_content = match.group(1)
            # HTML 엔티티 디코딩
            import html as html_module
            code_content_decoded = html_module.unescape(code_content)
            
            button_html = (
                '<div style="position: relative;">'
                f'<button class="copy-button" onclick="copyToClipboard(this)" data-code="{html_module.escape(code_content_decoded)}">'
                'Copy'
                '</button>'
                f'<pre><code>{code_content}</code></pre>'
                '</div>'
                '<script>'
                'function copyToClipboard(button) {'
                '    const code = button.getAttribute("data-code");'
                '    navigator.clipboard.writeText(code).then(() => {'
                '        button.textContent = "Copied!";'
                '        setTimeout(() => button.textContent = "Copy", 2000);'
                '    });'
                '}'
                '</script>'
            )
            return button_html
        
        # <pre><code>...</code></pre> 패턴을 찾아서 복사 버튼 추가
        pattern = r'<pre><code[^>]*>(.*?)</code></pre>'
        html = re.sub(pattern, add_copy_button, html, flags=re.DOTALL)
        return html

# --- YouTube Transcript Helper ---
# --- YouTube Transcript Helper ---
def get_youtube_transcript(video_id, **kwargs):
    proxy_disabled = kwargs.get("proxy_disabled", True)
    if proxy_disabled:
        try:
            transcript_list = YouTubeTranscriptApi.get_transcript(video_id, languages=("ko",))
            return " ".join([item['text'] for item in transcript_list])
        except Exception as e:
            logging.error(f"Error fetching YouTube transcript: {e}")
            try:
                transcript_list = YouTubeTranscriptApi.get_transcript(video_id, languages=("en",))
                return " ".join([item['text'] for item in transcript_list])
            except Exception as e:
                logging.error(f"Error fetching YouTube transcript: {e}")
                return f"Error fetching transcript: {str(e)}"
    else:
        Proxy_http = kwargs.get("Proxy_http", "http://168.219.61.252:8080")
        Proxy_https = kwargs.get("Proxy_https", "http://168.219.61.252:8080")
        try:
            transcript_list = YouTubeTranscriptApi.get_transcript(video_id, languages=("ko",), proxies={"http": Proxy_http, "https": Proxy_https}, verify=False)
            return " ".join([item['text'] for item in transcript_list])
        except Exception as e:
            logging.error(f"Error fetching YouTube transcript: {e}")
            try:
                transcript_list = YouTubeTranscriptApi.get_transcript(video_id, languages=("en",), proxies={"http": Proxy_http, "https": Proxy_https}, verify=False)
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
# --- Clipboard Item Class ---
# --- Enhanced Clipboard Item Class with Hide Functionality ---
class ClipboardItem:
    def __init__(self, data_type, data, timestamp=None):
        self.data_type = data_type
        self.data = data
        self.timestamp = timestamp or time.time()
        self.pinned = False  # 고정 상태
        self.hidden = False  # 숨김 상태 추가

    def to_dict(self):
        data_dict = {
            "type": self.data_type, 
            "timestamp": self.timestamp, 
            "pinned": self.pinned,
            "hidden": self.hidden  # 숨김 상태 저장
        }
        
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
        pinned = data_dict.get("pinned", False)
        hidden = data_dict.get("hidden", False)  # 숨김 상태 로드
        
        if data_type == "text":
            item = cls("text", content, timestamp)
            item.pinned = pinned
            item.hidden = hidden
            return item
        elif data_type == "image" and content:
            try:
                img_data = base64.b64decode(content)
                pixmap = QPixmap()
                if pixmap.loadFromData(img_data):
                    item = cls("image", pixmap, timestamp)
                    item.pinned = pinned
                    item.hidden = hidden
                    return item
                else:
                    logging.warning("Failed to load image data from dict")
            except Exception as e:
                logging.error(f"Error decoding image from dict: {e}")
        return None
# --- Assistant Widget ---
class AssistantWidget(QWidget):
    send_conversation_signal = Signal(list)
    web_search_signal = Signal(str)
    summarize_conversation_signal = Signal()

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
        
        # 향상된 대화 뷰 (마크다운 지원)
        self.conversation_view = EnhancedAssistantWidget()
        layout.addWidget(self.conversation_view)
        
        # 도구 영역
        tools_layout = QHBoxLayout()
        self.search_button = QPushButton("Web Search")
        self.search_button.setToolTip("Search the web for information")
        self.summarize_button = QPushButton("Summarize")
        self.summarize_button.setToolTip("Summarize the conversation")
        self.new_chat_button = QPushButton("New Chat")
        self.new_chat_button.setToolTip("Start a new conversation")
        tools_layout.addWidget(self.search_button)
        tools_layout.addWidget(self.summarize_button)
        tools_layout.addWidget(self.new_chat_button)
        tools_layout.addStretch()
        layout.addLayout(tools_layout)
        
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
        self.search_button.clicked.connect(self.handle_web_search)
        self.summarize_button.clicked.connect(self.handle_summarize)

    def handle_web_search(self):
        query = self.prompt_input.text().strip()
        if not query:
            QMessageBox.warning(self, "Empty Search", "Please enter a search query.")
            return
        
        if not self.google_api_key or not self.google_cx:
            QMessageBox.warning(self, "API Keys Missing", "Google API Key and Custom Search Engine ID are required for web search. Please configure them in settings.")
            return
        
        self.web_search_signal.emit(query)
        self.append_text_to_view(f"\\n**Searching the web for:** {query}\\n")
        self.prompt_input.clear()

    def perform_web_search(self, query):
        try:
            search_results = search_google(query, self.google_api_key, self.google_cx)
            if not search_results:
                self.append_text_to_view("\\n**No search results found.**\\n")
                return
            
            results_text = "\\n**Web Search Results:**\\n\\n"
            for i, result in enumerate(search_results, 1):
                results_text += f"{i}. **{result['title']}**\\n"
                results_text += f"   {result['link']}\\n"
                results_text += f"   {result['snippet']}\\n\\n"
            
            self.append_text_to_view(results_text)
            
            # 검색 결과를 대화 히스토리에 추가
            self.conversation_history.append({
                "role": "system",
                "content": f"Web search results for query '{query}': {json.dumps(search_results)}"
            })
        except Exception as e:
            logging.error(f"Error performing web search: {e}")
            self.append_text_to_view(f"\\n**Error performing web search:** {str(e)}\\n")

    def handle_summarize(self):
        if len(self.conversation_history) < 3:
            QMessageBox.information(self, "Not Enough Content", "The conversation is too short to summarize.")
            return
        
        self.summarize_conversation_signal.emit()
        self.append_text_to_view("\\n**Summarizing the conversation...**\\n")

    def send_prompt(self):
        prompt_text = self.prompt_input.text().strip()
        if not prompt_text:
            return
        
        # 대화 뷰에 추가
        self.append_text_to_view(f"\\n**You:** {prompt_text}\\n**Assistant:** ")
        
        # 일반 프롬프트만 추가
        self.conversation_history.append({"role": "user", "content": prompt_text})
        
        # Clear input and disable send button
        self.prompt_input.clear()
        self.send_button.setEnabled(False)
        self.new_chat_button.setEnabled(False)
        
        # Reset buffer for assistant response
        self.current_assistant_response = ""
        
        # 대화 전송
        self.send_conversation_signal.emit(self.conversation_history)

    @Slot(str)
    def append_text_to_view(self, text):
        # 마크다운 형식으로 텍스트 추가
        self.conversation_view.append_markdown_text(text)

    @Slot(str)
    def handle_stream_chunk(self, chunk):
        self.current_assistant_response += chunk
        # 스트리밍 중에는 임시로 일반 텍스트로 표시
        cursor = self.conversation_view.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(chunk)
        self.conversation_view.setTextCursor(cursor)

    @Slot()
    def clear_conversation(self):
        self.conversation_view.clear()
        self.prompt_input.clear()
        self.conversation_history = []
        self.summarized_history = ""
        self.current_assistant_response = ""
        self.send_button.setEnabled(True)
        self.new_chat_button.setEnabled(True)
        logging.info("Assistant conversation cleared.")

    @Slot()
    def on_stream_finished(self):
        if self.current_assistant_response:
            self.conversation_history.append({"role": "assistant", "content": self.current_assistant_response})
        
        self.send_button.setEnabled(True)
        self.new_chat_button.setEnabled(True)
        logging.info(f"Assistant stream finished. History size: {len(self.conversation_history)}")

# --- Settings Dialog ---
class SettingsDialog(QDialog):
    settings_updated_signal = Signal()
    
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
        
        # WebUI Assistant Settings
        webui_group = QGroupBox("Open WebUI Assistant")
        webui_layout = QFormLayout(webui_group)
        
        self.webui_endpoint_edit = QLineEdit()
        self.webui_endpoint_edit.setPlaceholderText("http://localhost:8080")
        webui_layout.addRow("Endpoint URL:", self.webui_endpoint_edit)
        
        self.webui_apikey_edit = QLineEdit()
        self.webui_apikey_edit.setEchoMode(QLineEdit.Password)
        webui_layout.addRow("API Key (Optional):", self.webui_apikey_edit)
        
        # 프록시 예외 설정 추가
        self.disable_proxy_checkbox = QCheckBox("Disable Proxy for AI Endpoint")
        self.disable_proxy_checkbox.setToolTip("Use direct connection without system proxy (helps with SSL issues)")
        webui_layout.addRow(self.disable_proxy_checkbox)
        
        # 모델 콤보박스 설정 부분
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

    def load_settings_values(self):
        default_notes_dir = os.path.join(QStandardPaths.writableLocation(QStandardPaths.AppDataLocation), SETTINGS_APP, "Notes")
        self.notes_dir_edit.setText(self.settings.value("notesDirectory", defaultValue=default_notes_dir))
        
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
            
            if isinstance(result, list):
                for model in result:
                    if isinstance(model, dict) and "id" in model:
                        models.append({"id": model.get("id", ""), "name": model.get("name", model.get("id", ""))})
                    elif isinstance(model, str):
                        models.append({"id": model, "name": model})
            
            if models:
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
                self.webui_model_combo.clear()
                QMessageBox.warning(self, "No Models", "No models found at the specified endpoint.")
                self.settings.setValue("webui/available_models", [])
                
        except Exception as e:
            QMessageBox.critical(self, "Fetch Error", f"Failed to fetch models: {e}")
            self.webui_model_combo.clear()
            self.settings.setValue("webui/available_models", [])

    def save_and_close(self):
        self.settings.setValue("notesDirectory", self.notes_dir_edit.text())
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
        self.proxy_disabled = proxy_disabled

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
                with requests.post(url, headers=headers, json=payload, stream=True, timeout=300, verify=False, proxies={"http": Proxy_http, "https": Proxy_https}) as response:
                    self._process_stream_response(response)
            else:
                with requests.post(url, headers=headers, json=payload, stream=True, timeout=300) as response:
                    self._process_stream_response(response)
        except requests.exceptions.Timeout:
            self.error.emit("Connection timed out.")
        except requests.exceptions.RequestException as e:
            error_detail = response.text if 'response' in locals() else "Unknown error"
            logging.error(f"Network error during chat: {e}. Details: {error_detail}")
            self.error.emit(f"Network error: {e}\\n{error_detail[:200]}")
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

# --- Main Window ---
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
        
        # QSplitter로 모든 위젯을 감싸기
        self.splitter = QSplitter(Qt.Vertical, self)
        self.setCentralWidget(self.splitter)

        self.clipboard_widget_content = self.create_clipboard_widget()
        self.clipboard_draggable = DraggableWidget("Clipboard History", self.clipboard_widget_content)
        self.process_widget_content = self.create_process_widget()
        self.process_draggable = DraggableWidget("Process Manager", self.process_widget_content)
        self.notepad_widget_content = self.create_notepad_widget()
        self.notepad_draggable = DraggableWidget("Notes", self.notepad_widget_content)
        self.assistant_widget = AssistantWidget()
        self.assistant_draggable = DraggableWidget("Assistant", self.assistant_widget)

        self.splitter.addWidget(self.clipboard_draggable)
        self.splitter.addWidget(self.process_draggable)
        self.splitter.addWidget(self.notepad_draggable)
        self.splitter.addWidget(self.assistant_draggable)

        # 기본 높이 동일하게
        default_height = int(self.height() / 4) if self.height() > 0 else 200
        self.splitter.setSizes([default_height] * 4)

        # splitter 상태 저장/복원
        splitter_state = self.settings.value("splitter/state")
        if splitter_state:
            self.splitter.restoreState(splitter_state)

        self.load_settings()
        
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
        
        self._drag_active = False
        self._drag_pos = None

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
        
        self.load_settings()
        
        if old_notes_dir != self.notes_directory:
            self.save_all_notes()
            self.load_notes()
        
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
        # 중복 제목 라벨 삭제
        # layout.addWidget(QLabel("Clipboard History (Max 30)"))
        self.clipboard_list = QListWidget()
        self.clipboard_list.setIconSize(QSize(64, 64))
        self.clipboard_list.itemDoubleClicked.connect(self.on_clipboard_item_activated)
        layout.addWidget(self.clipboard_list)
        return widget

    def create_process_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        # 중복 제목 라벨 삭제
        # layout.addWidget(QLabel("Process Manager"))
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
        
        tools_layout.addWidget(add_tab_button)
        tools_layout.addWidget(save_button)
        tools_layout.addWidget(load_button)
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
        QMessageBox.critical(self, "Assistant Error", f"An error occurred:\\n{error_message}")
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

    def apply_stylesheet(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #f8f9fa; }
            QPushButton { 
                background-color: #e9ecef; 
                border: 1px solid #ced4da; 
                padding: 6px 12px; 
                border-radius: 4px; 
                color: #495057; 
            }
            QPushButton:hover { background-color: #dee2e6; }
            QPushButton:pressed { background-color: #ced4da; }
            QLineEdit, QTextEdit, QListWidget, QPlainTextEdit, QComboBox { 
                border: 1px solid #ced4da; 
                padding: 5px; 
                background-color: #ffffff; 
                border-radius: 4px; 
                color: #212529; 
            }
            QLabel { 
                color: #495057; 
                font-weight: bold; 
                padding-bottom: 5px; 
            }
            QListWidget { background-color: #f8f9fa; }
            QListWidget::item { 
                padding: 5px; 
                border-bottom: 1px solid #eee; 
            }
            QListWidget::item:selected { 
                background-color: #cfe2ff; 
                color: #000; 
                border-bottom: 1px solid #b9d4ff; 
            }
            QListWidget::item:selected:!active { 
                background-color: #e0e0e0; 
                color: #000; 
            }
            QStatusBar { 
                background-color: #e9ecef; 
                color: #495057; 
            }
            QTabWidget::pane { 
                border: 1px solid #dee2e6; 
                background-color: #ffffff; 
                border-radius: 4px; 
            }
            QTabBar::tab { 
                background: #e9ecef; 
                border: 1px solid #dee2e6; 
                border-bottom: none; 
                padding: 6px 10px; 
                min-width: 60px; 
                border-top-left-radius: 4px; 
                border-top-right-radius: 4px; 
            }
            QTabBar::tab:selected { background: #ffffff; }
            QTabBar::tab:hover { background: #f1f3f5; }
            QGroupBox { margin-top: 10px; }
            QGroupBox::title { 
                subcontrol-origin: margin; 
                subcontrol-position: top left; 
                padding: 0 3px; 
            }
            QPlainTextEdit { background-color: #f8f9fa; }
            QProgressBar { 
                border: 1px solid #ced4da; 
                border-radius: 4px; 
                text-align: center; 
                background-color: #f8f9fa; 
            }
            QProgressBar::chunk { 
                background-color: #0d6efd; 
                width: 10px; 
                margin: 0.5px; 
            }
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
        elif event.type() == QApplication.focusChanged:
            if not QGuiApplication.focusWindow():
                logging.debug("Application lost focus.")
                if self.auto_hide_enabled and self.isVisible() and not self.is_mouse_over_window:
                    logging.debug("Application lost focus, sidebar visible, mouse not over -> hiding.")
                    self.hide_window()
        
        return super().eventFilter(obj, event)

    def closeEvent(self, event):
        # splitter 상태 저장
        self.settings.setValue("splitter/state", self.splitter.saveState())
        super().closeEvent(event)

    # Enhanced Clipboard Methods with Action Buttons
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
                
                # 고정되지 않은 아이템만 삭제
                while len(self.clipboard_history) > MAX_CLIPBOARD_HISTORY:
                    # 가장 오래된 고정되지 않은 아이템 찾기
                    for i in range(len(self.clipboard_history) - 1, -1, -1):
                        if not self.clipboard_history[i].pinned:
                            self.clipboard_history.pop(i)
                            break
                    else:
                        # 모든 아이템이 고정된 경우 루프 탈출
                        break
                
                self.update_clipboard_list_ui()
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
                # 사용자 정의 위젯으로 아이템 생성
                item_widget = ClipboardItemWidget(item, i, self)
                list_item = QListWidgetItem()
                list_item.setSizeHint(item_widget.sizeHint())
                list_item.setData(Qt.UserRole, i)
                
                self.clipboard_list.addItem(list_item)
                self.clipboard_list.setItemWidget(list_item, item_widget)
        except Exception as e:
            logging.error(f"Error updating clipboard UI: {e}", exc_info=True)

    def delete_clipboard_item(self, index):
        if 0 <= index < len(self.clipboard_history) and not self.clipboard_history[index].pinned:
            del self.clipboard_history[index]
            self.update_clipboard_list_ui()

    def hide_clipboard_item(self, index):
        # 임시로 숨기기 기능 (실제로는 삭제와 동일하게 처리)
        self.delete_clipboard_item(index)

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
                details.append(f"- {name} ({pid}){' [CRITICAL]' if is_crit else ''}")
                
                if is_crit:
                    critical = True
            
            msg = f"Terminate the following {len(to_kill)} process(es)?\\n\\n" + "\\n".join(details)
            
            if critical:
                msg += "\\n\\nWARNING: One or more selected processes appear critical..."
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
            
            QMessageBox.information(self, "Process Found", f"Found process(es) for port {port}:\\n\\n" + "\\n".join(process_info))
        
        except psutil.AccessDenied:
            QMessageBox.critical(self, "Access Denied", "Cannot retrieve network info. Try admin/root.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error finding process by port: {e}")

    # --- Enhanced Notepad Methods ---
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
        current_index = self.notepad_tabs.currentIndex()
        for index, changed in list(self.notes_changed.items()):
            if changed and index != current_index:
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
        
        if isinstance(widget, MarkdownEditor):  # MarkdownEditor 검사
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
                return True
            except Exception as e:
                QMessageBox.warning(self, "Save Error", f"Failed to save note '{tab_name}':\\n{e}")
                return False
        
        return False

    def get_note_filepath(self, note_name):
        # .md 확장자 사용
        safe_filename = re.sub(r'[\\/*?:"<>|]', "_", note_name) + ".md"
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
            
            # MarkdownEditor 사용
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

    def save_current_note(self):
        index = self.notepad_tabs.currentIndex()
        if index != -1:
            if self.save_note(index, mark_saved=True):
                tab_text = self.notepad_tabs.tabText(index)
                if tab_text.endswith(" *"):
                    tab_text = tab_text[:-2]
                self.log_status(f"Note '{tab_text}' saved successfully.", 3000)

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
            QMessageBox.warning(self, "Load Error", f"Failed to load note from '{filepath}':\\n{e}")

    def rename_current_notepad_tab(self):
        idx = self.notepad_tabs.currentIndex()
        if idx == -1:
            return
        
        old_name_display = self.notepad_tabs.tabText(idx)
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
                if isinstance(current_widget, MarkdownEditor):
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
                    # 현재 인덱스를 선택된 탭으로 설정
                    self.notepad_tabs.setCurrentIndex(index)
                    self.rename_current_notepad_tab()
                elif action == close_action:
                    self.close_notepad_tab(index)
        except Exception as e:
            logging.error(f"Error in notepad context menu: {e}")

    # Auto Hide Methods
    @Slot(bool)
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
            
            edge_threshold = 5  # 5픽셀로 변경
            is_near_right_edge = mouse_pos.x() >= (screen_geo.right() - edge_threshold) and screen_geo.top() <= mouse_pos.y() <= screen_geo.bottom()
            
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

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_active = True
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._drag_active and event.buttons() & Qt.LeftButton:
            new_pos = event.globalPosition().toPoint() - self._drag_pos
            self.move(new_pos)
            event.accept()
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_active = False
            event.accept()
        super().mouseReleaseEvent(event)

    @Slot(str, int)
    def log_status(self, message, timeout=0):
        try:
            self.status_bar.showMessage(message, timeout)
            logging.debug(f"Status Bar: {message}")
        except Exception as e:
            logging.error(f"Error showing status message: {e}")

    def schedule_sync(self, data_type, details=None):
        pass  # P2P 기능 제거됨

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
            msg_box.setText(f"An unhandled error occurred and the application must close.\\n\\n{e}\\n\\nSee log file for details.")
            msg_box.exec()
        except:
            pass
        sys.exit(1)
