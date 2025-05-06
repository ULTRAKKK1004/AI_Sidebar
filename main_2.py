# main_modified.py
import sys
import os
import psutil
import re
import base64
import json
import requests # Needed for OpenWebUI API calls
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

import pyautogui # Added for mouse position

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QTabWidget, QLabel,
    QTextEdit, QListWidget, QPushButton, QLineEdit, QHBoxLayout, QSplitter,
    QListWidgetItem, QMessageBox, QInputDialog, QFileDialog, QAbstractItemView,
    QSystemTrayIcon, QMenu, QDialog, QFormLayout, QDialogButtonBox,
    QGroupBox, QTabBar, QCheckBox, QComboBox, QPlainTextEdit # Added ComboBox, PlainTextEdit
)
from PySide6.QtCore import (
    Qt, QTimer, QSettings, QSize, QMimeData, QDir, QStandardPaths, QRect,
    QByteArray, QBuffer, QIODevice, Signal, QObject, QThread, Slot, QEvent,
    QMetaObject, Q_ARG, QPoint # Added for cross-thread signals
)
from PySide6.QtGui import (
    QClipboard, QPixmap, QImage, QAction, QIcon, QGuiApplication,
    QShortcut, QKeySequence, QScreen, QCloseEvent, QTextCursor, QPainter # Added QTextCursor
)

import platform # Added for OS detection

# --- Constants ---
MAX_CLIPBOARD_HISTORY = 30
# Platform-specific critical processes
if platform.system() == "Windows":
    CRITICAL_PROCESSES = [
        "system idle process", "system", "smss.exe", "csrss.exe",
        "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe",
        "explorer.exe"
    ]
elif platform.system() == "Linux":
    # Define critical processes for Linux (example, adjust as needed)
    CRITICAL_PROCESSES = [
        "systemd", "kthreadd", "init", "dbus-daemon", "NetworkManager",
        "Xorg", "gnome-shell", "pulseaudio" # Add more critical Linux processes
    ]
else:
    CRITICAL_PROCESSES = [] # Default for other OS
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
LOG_FILE_MAX_BYTES = 5 * 1024 * 1024 # 5 MB
LOG_FILE_BACKUP_COUNT = 5

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

# --- P2P Peer Class --- (No changes)
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

# --- Settings Dialog --- (No changes needed for this request)
class SettingsDialog(QDialog):
    settings_updated_signal = Signal() # Signal to notify main window of changes

    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.setMinimumWidth(500) # Increased width

        main_layout = QVBoxLayout(self)

        # --- General Settings ---
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

        # --- P2P Sync Settings ---
        p2p_group = QGroupBox("P2P Synchronization")
        p2p_layout = QFormLayout(p2p_group)
        self.p2p_enabled_checkbox = QCheckBox("Enable P2P Synchronization")
        p2p_layout.addRow(self.p2p_enabled_checkbox)
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

        # --- Open WebUI Settings ---
        webui_group = QGroupBox("Open WebUI Assistant")
        webui_layout = QFormLayout(webui_group)
        self.webui_endpoint_edit = QLineEdit()
        self.webui_endpoint_edit.setPlaceholderText("http://localhost:8080")
        webui_layout.addRow("Endpoint URL:", self.webui_endpoint_edit)
        self.webui_apikey_edit = QLineEdit()
        self.webui_apikey_edit.setEchoMode(QLineEdit.Password)
        webui_layout.addRow("API Key (Optional):", self.webui_apikey_edit)
        model_layout = QHBoxLayout()
        self.webui_model_combo = QComboBox()
        self.webui_model_combo.setMinimumWidth(200)
        fetch_models_button = QPushButton("Fetch Models")
        fetch_models_button.clicked.connect(self.fetch_webui_models)
        model_layout.addWidget(self.webui_model_combo)
        model_layout.addWidget(fetch_models_button)
        webui_layout.addRow("Model:", model_layout)
        main_layout.addWidget(webui_group)

        # --- Dialog Buttons ---
        button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.save_and_close)
        button_box.rejected.connect(self.reject)
        main_layout.addWidget(button_box)

        self.load_settings_values()

    def load_settings_values(self):
        # General
        default_notes_dir = os.path.join(QStandardPaths.writableLocation(QStandardPaths.AppDataLocation), SETTINGS_APP, "Notes")
        self.notes_dir_edit.setText(self.settings.value("notesDirectory", defaultValue=default_notes_dir))

        # P2P
        self.p2p_enabled_checkbox.setChecked(self.settings.value("p2p/enabled", defaultValue=False, type=bool))
        self.sync_user_edit.setText(self.settings.value("p2p/username", defaultValue=""))
        self.sync_pass_edit.setText(self.settings.value("p2p/password", defaultValue=""))
        self.p2p_port_edit.setText(str(self.settings.value("p2p/listenPort", defaultValue=DEFAULT_P2P_PORT)))
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

        # Open WebUI
        self.webui_endpoint_edit.setText(self.settings.value("webui/endpoint", defaultValue=""))
        self.webui_apikey_edit.setText(self.settings.value("webui/apikey", defaultValue=""))
        # Load saved models into combo box initially, then try fetching if endpoint exists
        saved_models = self.settings.value("webui/available_models", defaultValue=[])
        selected_model = self.settings.value("webui/selected_model", defaultValue="")
        self.webui_model_combo.clear()
        if saved_models:
            # saved_models might be list of dicts or list of strings, handle both
            if saved_models and isinstance(saved_models[0], dict):
                model_names = [m.get('name', m.get('id', '')) for m in saved_models]
            else:
                model_names = saved_models # Assume list of strings
            self.webui_model_combo.addItems(model_names)
            if selected_model in model_names:
                self.webui_model_combo.setCurrentText(selected_model)
        elif self.webui_endpoint_edit.text():
             # Try fetching on load if endpoint is set but no models saved
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
        # Ensure endpoint ends with /api/models
        if not endpoint.endswith("/"): endpoint += "/"
        url = endpoint + "api/models"

        headers = {"Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        try:
            logging.info(f"Fetching models from {url}")
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            res_text = response.content.decode('utf-8')
            result = json.loads(res_text)

            logging.info(f"OpenWebUI response structure: {list(result.keys()) if isinstance(result, dict) else 'Response is not a dictionary'}")

            # Handle different possible response structures
            if isinstance(result, list):
                # Response is directly a list of models
                for model in result:
                    if isinstance(model, dict) and 'id' in model:
                        models.append({
                            "id": model.get('id', ''),
                            "name": model.get('name', model.get('id', ''))
                        })
                    elif isinstance(model, str):
                        models.append({"id": model, "name": model})
            elif isinstance(result, dict):
                # Models are under 'data' key
                if 'data' in result and isinstance(result['data'], list):
                    for model in result['data']:
                        if isinstance(model, dict):
                            models.append({
                                "id": model.get('id', ''),
                                "name": model.get('name', model.get('id', ''))
                            })
                        elif isinstance(model, str):
                            models.append({"id": model, "name": model})
                # Models are under 'models' key
                elif 'models' in result and isinstance(result['models'], list):
                    for model in result['models']:
                        if isinstance(model, dict):
                            models.append({
                                "id": model.get('id', model.get('name', '')),
                                "name": model.get('name', model.get('id', ''))
                            })
                        elif isinstance(model, str):
                            models.append({"id": model, "name": model})

            if models:
                logging.info(f"Found models: {models}")
                current_selection = self.webui_model_combo.currentText()
                self.webui_model_combo.clear()
                model_name_list = [m['name'] for m in models]
                self.webui_model_combo.addItems(model_name_list)
                if current_selection in model_name_list:
                    self.webui_model_combo.setCurrentText(current_selection)
                elif model_name_list: # Select first model if previous selection invalid
                    self.webui_model_combo.setCurrentIndex(0)
                QMessageBox.information(self, "Success", f"Successfully fetched {len(models)} models.")
                # Save fetched models (list of dicts) for next load
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
        # General
        self.settings.setValue("notesDirectory", self.notes_dir_edit.text())

        # P2P
        self.settings.setValue("p2p/enabled", self.p2p_enabled_checkbox.isChecked())
        self.settings.setValue("p2p/username", self.sync_user_edit.text())
        self.settings.setValue("p2p/password", self.sync_pass_edit.text())
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

        # Open WebUI
        self.settings.setValue("webui/endpoint", self.webui_endpoint_edit.text().strip())
        self.settings.setValue("webui/apikey", self.webui_apikey_edit.text().strip())
        self.settings.setValue("webui/selected_model", self.webui_model_combo.currentText())
        # Available models are saved during fetch

        self.settings_updated_signal.emit() # Notify main window
        self.accept()

# --- Clipboard Item Class --- (No changes)
class ClipboardItem:
    def __init__(self, data_type, data, timestamp=None):
        self.data_type = data_type # 'text' or 'image'
        self.data = data # str or QPixmap
        self.timestamp = timestamp or time.time()

    def to_dict(self):
        data_dict = {"type": self.data_type, "timestamp": self.timestamp}
        if self.data_type == "text":
            data_dict["content"] = self.data
        elif self.data_type == "image" and isinstance(self.data, QPixmap):
            try:
                buffer = QBuffer()
                buffer.open(QIODevice.WriteOnly)
                # Save as PNG to preserve transparency, adjust quality if needed
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

# --- P2P Manager --- (No changes needed for this request)
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
        self.load_config()

    def load_config(self):
        try:
            self.p2p_enabled = self.settings.value("p2p/enabled", defaultValue=False, type=bool)
            self.username = self.settings.value("p2p/username", "")
            self.password = self.settings.value("p2p/password", "")
            self.listen_port = int(self.settings.value("p2p/listenPort", DEFAULT_P2P_PORT))
            self.derive_key()
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
            return
        try:
            salt_hex = self.settings.value("p2p/salt")
            if salt_hex:
                salt = bytes.fromhex(salt_hex)
            else:
                salt = os.urandom(SALT_SIZE)
                self.settings.setValue("p2p/salt", salt.hex())
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(), length=AES_KEY_SIZE, salt=salt,
                iterations=PBKDF2_ITERATIONS, backend=default_backend()
            )
            self.encryption_key = kdf.derive(self.password.encode("utf-8"))
            logging.info("Encryption key derived.")
        except Exception as e:
            self.encryption_key = None
            logging.error(f"Error deriving encryption key: {e}")

    def encrypt_data(self, data):
        if not self.encryption_key: return None
        try:
            aesgcm = AESGCM(self.encryption_key)
            nonce = os.urandom(NONCE_SIZE)
            json_data = json.dumps(data).encode("utf-8")
            encrypted_data = aesgcm.encrypt(nonce, json_data, None)
            return nonce + encrypted_data
        except Exception as e:
            logging.error(f"Encryption failed: {e}")
            return None

    def decrypt_data(self, encrypted_payload):
        if not self.encryption_key: return None
        if len(encrypted_payload) < NONCE_SIZE + TAG_SIZE: return None
        try:
            nonce = encrypted_payload[:NONCE_SIZE]
            encrypted_data = encrypted_payload[NONCE_SIZE:]
            aesgcm = AESGCM(self.encryption_key)
            decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
            return json.loads(decrypted_data.decode("utf-8"))
        except Exception as e:
            logging.warning(f"Decryption failed: {e}")
            return None

    @Slot()
    def start(self):
        if self.running: return
        self.load_config()
        if not self.p2p_enabled:
            logging.info("P2P sync is disabled in settings.")
            self.log_message.emit("P2P Disabled")
            return
        if not self.username or not self.password:
            logging.warning("P2P sync cannot start: Username or password missing.")
            self.log_message.emit("P2P Creds Missing")
            self.p2p_enabled = False
            return
        if not self.peers:
            logging.warning("P2P sync cannot start: No peers configured.")
            self.log_message.emit("P2P No Peers")
            self.p2p_enabled = False
            return
        if not self.encryption_key:
             logging.error("P2P sync cannot start: Encryption key derivation failed.")
             self.log_message.emit("P2P Key Error")
             self.p2p_enabled = False
             return
        self.running = True
        logging.info(f"Starting P2P Manager on port {self.listen_port}...")
        self.log_message.emit(f"P2P Starting (Port: {self.listen_port})")
        listen_thread = threading.Thread(target=self._listen_for_peers, daemon=True, name="P2PListenThread")
        listen_thread.start()
        connect_thread = threading.Thread(target=self._connect_to_peers, daemon=True, name="P2PConnectThread")
        connect_thread.start()

    @Slot()
    def stop(self):
        if not self.running: return
        self.running = False
        logging.info("Stopping P2P Manager...")
        if self.listen_socket:
            try: self.listen_socket.close()
            except Exception as e: logging.error(f"Error closing listen socket: {e}")
            self.listen_socket = None
        active_connections = []
        for peer_key, peer in list(self.peers.items()):
            if peer.connection:
                active_connections.append(peer.connection)
                peer.connection = None
            peer.status = "Disconnected"
            peer.authenticated = False
            try: self.peer_status_changed.emit(peer.address, peer.port, peer.status)
            except RuntimeError: pass
        time.sleep(0.1)
        for conn in active_connections:
             try: conn.shutdown(socket.SHUT_RDWR); conn.close()
             except Exception as e: logging.debug(f"Error force closing peer connection: {e}")
        logging.info("P2P Manager stopped.")
        self.log_message.emit("P2P Stopped")

    def _listen_for_peers(self):
        try:
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listen_socket.bind(("0.0.0.0", self.listen_port))
            self.listen_socket.listen(5)
            logging.info(f"Listening on 0.0.0.0:{self.listen_port}")
        except Exception as e:
            logging.error(f"Error starting listener: {e}")
            self.log_message.emit(f"P2P Listen Error: {e}")
            self.running = False
            return
        while self.running:
            try:
                conn, addr = self.listen_socket.accept()
                logging.info(f"Incoming connection from {addr[0]}:{addr[1]}")
                handler_thread = threading.Thread(target=self._handle_peer_connection, args=(conn, addr), daemon=True, name=f"P2PHandler-{addr[0]}")
                handler_thread.start()
            except OSError:
                if self.running: logging.warning("Listener socket closed or error.")
                break
            except Exception as e:
                if self.running: logging.error(f"Listener accept error: {e}")
                time.sleep(1)
        if self.listen_socket:
            try: self.listen_socket.close()
            except: pass
        logging.info("Listener thread stopped.")

    def _connect_to_peers(self):
        while self.running:
            connected_peers = 0
            for peer_key, peer in list(self.peers.items()):
                if not self.running: break
                if not peer.connection:
                    try:
                        self.peer_status_changed.emit(peer.address, peer.port, "Connecting...")
                        conn = socket.create_connection((peer.address, peer.port), timeout=5)
                        peer.connection = conn
                        peer.status = "Connected (Authenticating...)"
                        self.peer_status_changed.emit(peer.address, peer.port, peer.status)
                        logging.info(f"Connected to {peer.address}:{peer.port}")
                        handler_thread = threading.Thread(target=self._handle_peer_connection, args=(conn, (peer.address, peer.port)), daemon=True, name=f"P2PHandler-{peer.address}")
                        handler_thread.start()
                        connected_peers += 1
                    except socket.timeout:
                        peer.status = "Timeout"
                        self.peer_status_changed.emit(peer.address, peer.port, peer.status)
                        peer.connection = None
                    except ConnectionRefusedError:
                        peer.status = "Refused"
                        self.peer_status_changed.emit(peer.address, peer.port, peer.status)
                        peer.connection = None
                    except Exception as e:
                        logging.warning(f"Failed to connect to {peer.address}:{peer.port}: {e}")
                        peer.status = "Error"
                        self.peer_status_changed.emit(peer.address, peer.port, peer.status)
                        peer.connection = None
                else:
                    connected_peers += 1
            if connected_peers == 0 and self.peers:
                 self.log_message.emit("P2P No Peers Connected")
            for _ in range(100):
                 if not self.running: break
                 time.sleep(0.1)
        logging.info("Connector thread stopped.")

    def _handle_peer_connection(self, conn, addr):
        peer_key = f"{addr[0]}:{addr[1]}"
        peer = self.peers.get(peer_key)
        is_known_peer = bool(peer)
        if not peer:
            peer = Peer(addr[0], addr[1], "Connected (Authenticating...)")
            logging.info(f"Handling unknown incoming peer {peer_key}")
        authenticated = False
        try:
            authenticated = self._perform_authentication(conn, peer)
        except Exception as auth_err:
             logging.error(f"Exception during authentication with {peer_key}: {auth_err}")
             authenticated = False
        if not authenticated:
            logging.warning(f"Authentication failed for {peer_key}. Closing connection.")
            if is_known_peer:
                 self.peers[peer_key].status = "Auth Failed"
                 self.peers[peer_key].connection = None
                 try: self.peer_status_changed.emit(peer.address, peer.port, "Auth Failed")
                 except RuntimeError: pass
            try: conn.close()
            except: pass
            return
        if is_known_peer:
            self.peers[peer_key].authenticated = True
            self.peers[peer_key].status = "Connected"
            try: self.peer_status_changed.emit(peer.address, peer.port, "Connected")
            except RuntimeError: pass
        else:
            logging.info(f"Authenticated unknown peer: {peer_key}. Connection will be handled but not stored permanently.")
            peer.authenticated = True
            peer.status = "Connected"
        buffer = b""
        msg_len = -1
        while self.running and (peer.connection if is_known_peer else conn):
            try:
                data = conn.recv(8192)
                if not data:
                    logging.info(f"Peer {peer_key} disconnected gracefully.")
                    break
                buffer += data
                while self.running:
                    if msg_len == -1 and len(buffer) >= 4:
                        msg_len = int.from_bytes(buffer[:4], "big")
                        buffer = buffer[4:]
                    if msg_len != -1 and len(buffer) >= msg_len:
                        encrypted_msg_payload = buffer[:msg_len]
                        buffer = buffer[msg_len:]
                        msg_len = -1
                        decrypted_msg = self.decrypt_data(encrypted_msg_payload)
                        if decrypted_msg:
                            logging.info(f'Received from {peer_key}: type {decrypted_msg.get("type")}')
                            try:
                                self.received_data.emit(decrypted_msg)
                            except RuntimeError:
                                pass
                        else:
                             logging.warning(f"Failed to decrypt message from {peer_key}. Ignoring.")
                    else: break
            except ConnectionResetError:
                logging.warning(f"Peer {peer_key} reset connection.")
                break
            except socket.timeout: continue
            except OSError as e:
                 logging.warning(f"Socket error with {peer_key}: {e}")
                 break
            except Exception as e:
                logging.error(f"Error receiving from {peer_key}: {e}", exc_info=True)
                break
        if is_known_peer:
            self.peers[peer_key].status = "Disconnected"
            self.peers[peer_key].connection = None
            self.peers[peer_key].authenticated = False
            try: self.peer_status_changed.emit(peer.address, peer.port, "Disconnected")
            except RuntimeError: pass
        try: conn.close()
        except: pass
        logging.info(f"Handler for {peer_key} finished.")

    def _perform_authentication(self, conn, peer):
        if not self.username or not self.password or not self.encryption_key: return False
        try:
            conn.settimeout(15)
            # Step 1 & 2: Send AUTH_INIT, Receive AUTH_INIT
            auth_init = {"type": "AUTH_INIT", "username": self.username}
            encrypted_init = self.encrypt_data(auth_init)
            if not encrypted_init: return False
            self._send_message(conn, encrypted_init)
            encrypted_resp = self._receive_message(conn)
            if not encrypted_resp: return False
            decrypted_resp = self.decrypt_data(encrypted_resp)
            if not decrypted_resp or decrypted_resp.get("type") != "AUTH_INIT" or decrypted_resp.get("username") != self.username:
                logging.warning(f"Auth step 1/2 failed with {peer.address}:{peer.port}. Invalid response: {decrypted_resp}")
                return False
            # Step 3 & 4: Send AUTH_CHALLENGE, Receive AUTH_RESPONSE
            challenge = os.urandom(32)
            challenge_msg = {"type": "AUTH_CHALLENGE", "challenge": base64.b64encode(challenge).decode()}
            encrypted_challenge = self.encrypt_data(challenge_msg)
            if not encrypted_challenge: return False
            self._send_message(conn, encrypted_challenge)
            encrypted_resp = self._receive_message(conn)
            if not encrypted_resp: return False
            decrypted_resp = self.decrypt_data(encrypted_resp)
            if not decrypted_resp or decrypted_resp.get("type") != "AUTH_RESPONSE":
                logging.warning(f"Auth step 3/4 failed with {peer.address}:{peer.port}. Invalid response type: {decrypted_resp.get('type')}")
                return False
            expected_response_hmac = hmac.new(self.encryption_key, challenge, hashlib.sha256).digest()
            received_response_b64 = decrypted_resp.get("response")
            if not received_response_b64: return False
            try: received_response_hmac = base64.b64decode(received_response_b64)
            except Exception: return False
            if not hmac.compare_digest(expected_response_hmac, received_response_hmac):
                logging.warning(f"Auth step 3/4 failed with {peer.address}:{peer.port}. HMAC mismatch.")
                return False
            # Step 5 & 6: Send AUTH_OK, Receive AUTH_OK
            auth_ok_msg = {"type": "AUTH_OK"}
            encrypted_ok = self.encrypt_data(auth_ok_msg)
            if not encrypted_ok: return False
            self._send_message(conn, encrypted_ok)
            encrypted_resp = self._receive_message(conn)
            if not encrypted_resp: return False
            decrypted_resp = self.decrypt_data(encrypted_resp)
            if not decrypted_resp or decrypted_resp.get("type") != "AUTH_OK":
                logging.warning(f"Auth step 5/6 failed with {peer.address}:{peer.port}. Did not receive AUTH_OK.")
                return False
            logging.info(f"Authentication successful with {peer.address}:{peer.port}")
            conn.settimeout(None) # Disable timeout for normal operation
            return True
        except socket.timeout:
            logging.warning(f"Authentication timed out with {peer.address}:{peer.port}")
            return False
        except Exception as e:
            logging.error(f"Authentication error with {peer.address}:{peer.port}: {e}", exc_info=True)
            return False

    def _send_message(self, conn, encrypted_payload):
        try:
            msg_len_bytes = len(encrypted_payload).to_bytes(4, "big")
            conn.sendall(msg_len_bytes + encrypted_payload)
        except Exception as e:
            logging.error(f"Error sending message: {e}")
            raise

    def _receive_message(self, conn):
        try:
            len_bytes = conn.recv(4)
            if not len_bytes or len(len_bytes) < 4: return None
            msg_len = int.from_bytes(len_bytes, "big")
            if msg_len > 10 * 1024 * 1024: # Limit message size (e.g., 10MB)
                logging.error(f"Received message too large: {msg_len} bytes")
                return None
            chunks = []
            bytes_recd = 0
            while bytes_recd < msg_len:
                chunk = conn.recv(min(msg_len - bytes_recd, 8192))
                if not chunk: return None
                chunks.append(chunk)
                bytes_recd += len(chunk)
            return b''.join(chunks)
        except Exception as e:
            logging.error(f"Error receiving message: {e}")
            return None

    @Slot(dict)
    def send_to_all_peers(self, data):
        if not self.running or not self.p2p_enabled: return
        encrypted_payload = self.encrypt_data(data)
        if not encrypted_payload: return
        sent_count = 0
        for peer_key, peer in list(self.peers.items()):
            if peer.connection and peer.authenticated:
                try:
                    self._send_message(peer.connection, encrypted_payload)
                    sent_count += 1
                except Exception as e:
                    logging.warning(f"Failed to send data to {peer_key}: {e}. Disconnecting.")
                    peer.status = "Send Error"
                    peer.authenticated = False
                    try: peer.connection.close()
                    except: pass
                    peer.connection = None
                    try: self.peer_status_changed.emit(peer.address, peer.port, peer.status)
                    except RuntimeError: pass
        logging.info(f"Sent data (type: {data.get('type')}) to {sent_count} authenticated peers.")

# --- WebUI Worker --- (Modified for conversation history)
class WebUIWorker(QObject):
    finished = Signal()
    error = Signal(str)
    models_fetched = Signal(list)
    stream_chunk = Signal(str)
    stream_finished = Signal()

    def __init__(self, endpoint, api_key, model=None, messages=None): # Changed prompt to messages
        super().__init__()
        self.endpoint = endpoint
        self.api_key = api_key
        self.model = model
        self.messages = messages if messages else [] # Store the list of messages
        self._running = True

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
            logging.info(f"Worker fetching models from {url}")
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            res_text = response.content.decode("utf-8")
            res_js = json.loads(res_text)
            # Handle different response structures for models
            models_data = []
            if isinstance(res_js, list):
                models_data = res_js
            elif isinstance(res_js, dict):
                if 'data' in res_js and isinstance(res_js['data'], list):
                    models_data = res_js['data']
                elif 'models' in res_js and isinstance(res_js['models'], list):
                    models_data = res_js['models']

            models = []
            for model in models_data:
                if isinstance(model, dict):
                    models.append({
                        "id": model.get('id', model.get('name', '')),
                        "name": model.get('name', model.get('id', ''))
                    })
                elif isinstance(model, str):
                    models.append({"id": model, "name": model})

            self.models_fetched.emit(models) # Emit list of dicts
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

        url = self.endpoint.rstrip("/") + "/api/chat/completions" # Standard OpenAI API endpoint
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": self.messages, # Use the full conversation history
            "stream": True
        }

        try:
            logging.info(f"Worker sending chat request to {url} for model {self.model} with {len(self.messages)} messages.")
            # logging.debug(f"Payload: {json.dumps(payload)}") # Uncomment for debugging
            with requests.post(url, headers=headers, json=payload, stream=True, timeout=300) as response:
                response.raise_for_status()
                buffer = ""
                for line in response.iter_lines(decode_unicode=True):
                    if not self._running: break
                    if line.startswith("data:"):
                        json_str = line[len("data:"):].strip()
                        if json_str == "[DONE]":
                            break
                        if json_str:
                            try:
                                data = json.loads(json_str)
                                # logging.debug(f"Stream data: {data}") # Uncomment for debugging
                                if "choices" in data and data["choices"]:
                                    delta = data["choices"][0].get("delta", {})
                                    message_content = delta.get("content", "")
                                    if message_content:
                                        self.stream_chunk.emit(message_content)
                                # Check for finish reason if needed (though [DONE] is more reliable)
                                # finish_reason = data["choices"][0].get("finish_reason")
                                # if finish_reason:
                                #     break
                            except json.JSONDecodeError:
                                logging.warning(f"JSON decode error in stream line: {line}")
                            except Exception as e:
                                logging.error(f"Error processing stream part: {e} - Line: {line}")

        except requests.exceptions.Timeout:
            self.error.emit("Connection timed out.")
        except requests.exceptions.RequestException as e:
            error_detail = "Unknown error"
            try:
                # Try to get more detailed error from response if available
                error_detail = response.text
            except Exception:
                pass
            logging.error(f"Network error during chat: {e}. Details: {error_detail}")
            self.error.emit(f"Network error during chat: {e}\n{error_detail[:200]}") # Show limited detail
        except Exception as e:
            logging.error(f"Unexpected error during chat: {e}", exc_info=True)
            self.error.emit(f"Unexpected error during chat: {e}")
        finally:
            self.stream_finished.emit()
            self.finished.emit()

    @Slot()
    def stop(self):
        self._running = False
        logging.info("WebUIWorker stop requested.")

# --- Assistant Widget --- (Modified for conversation history)
class AssistantWidget(QWidget):
    send_conversation_signal = Signal(list) # Emit the whole conversation history

    def __init__(self, parent=None):
        super().__init__(parent)
        self.conversation_history = [] # List to store messages [{"role": "user"/"assistant", "content": "..."}]
        self.current_assistant_response = "" # Buffer for incoming stream

        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        title_layout = QHBoxLayout()
        title_layout.addWidget(QLabel("Assistant"))
        title_layout.addStretch()
        self.new_chat_button = QPushButton("New Chat")
        self.new_chat_button.setToolTip("Start a new conversation")
        title_layout.addWidget(self.new_chat_button)
        layout.addLayout(title_layout)

        self.conversation_view = QPlainTextEdit()
        self.conversation_view.setReadOnly(True)
        # self.conversation_view.setStyleSheet("background-color: #e9ecef;") # Slightly different background
        layout.addWidget(self.conversation_view)

        prompt_layout = QHBoxLayout()
        self.prompt_input = QLineEdit()
        self.prompt_input.setPlaceholderText("Enter your prompt...")
        self.send_button = QPushButton("Send")
        prompt_layout.addWidget(self.prompt_input)
        prompt_layout.addWidget(self.send_button)
        layout.addLayout(prompt_layout)

        # Connect signals
        self.send_button.clicked.connect(self.send_prompt)
        self.prompt_input.returnPressed.connect(self.send_prompt)
        self.new_chat_button.clicked.connect(self.clear_conversation)

    def send_prompt(self):
        prompt_text = self.prompt_input.text().strip()
        if prompt_text:
            # Add user message to UI
            self.append_text_to_view(f"\n**You:** {prompt_text}\n**Assistant:** ")
            # Add user message to history
            self.conversation_history.append({"role": "user", "content": prompt_text})
            # Clear input and disable send button
            self.prompt_input.clear()
            self.send_button.setEnabled(False)
            self.new_chat_button.setEnabled(False)
            # Reset buffer for assistant response
            self.current_assistant_response = ""
            # Emit the full history
            self.send_conversation_signal.emit(self.conversation_history)

    @Slot(str)
    def append_text_to_view(self, text):
        """Appends text directly to the conversation view."""
        self.conversation_view.moveCursor(QTextCursor.End)
        self.conversation_view.insertPlainText(text)
        self.conversation_view.moveCursor(QTextCursor.End)

    @Slot(str)
    def handle_stream_chunk(self, chunk):
        """Appends a chunk of the assistant's response to the view and buffer."""
        self.append_text_to_view(chunk)
        self.current_assistant_response += chunk

    @Slot()
    def clear_conversation(self):
        self.conversation_view.clear()
        self.prompt_input.clear()
        self.conversation_history = []
        self.current_assistant_response = ""
        self.send_button.setEnabled(True)
        self.new_chat_button.setEnabled(True)
        logging.info("Assistant conversation cleared.")

    @Slot()
    def on_stream_finished(self):
        # Add the complete assistant response to history
        if self.current_assistant_response:
            self.conversation_history.append({"role": "assistant", "content": self.current_assistant_response})
        # Re-enable buttons
        self.send_button.setEnabled(True)
        self.new_chat_button.setEnabled(True)
        self.append_text_to_view("\n") # Add newline after response
        logging.info(f"Assistant stream finished. History size: {len(self.conversation_history)}")

# --- Main Window --- (Modified for Assistant history and signals)
class MainWindow(QMainWindow):
    send_p2p_data_signal = Signal(dict)
    # Signal: endpoint, api_key, model, messages_list
    start_webui_chat_signal = Signal(str, str, str, list)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SideBar Assistant - P2P")
        self.setWindowFlags(Qt.WindowStaysOnTopHint) # Allow standard frame for resizing

        self.settings = QSettings(SETTINGS_ORG, SETTINGS_APP)
        self.notes_directory = ""
        self.webui_endpoint = ""
        self.webui_apikey = ""
        self.webui_model = ""
        self.load_settings()

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

        # --- Main Layout: Vertical Splitter (Now with 4 sections) ---
        self.central_widget = QSplitter(Qt.Vertical)
        self.setCentralWidget(self.central_widget)

        # --- Create Widgets ---
        self.clipboard_widget = self.create_clipboard_widget()
        self.process_widget = self.create_process_widget()
        self.notepad_widget = self.create_notepad_widget()
        self.assistant_widget = AssistantWidget() # Create Assistant widget

        # --- Add widgets to splitter ---
        self.central_widget.addWidget(self.clipboard_widget)
        self.central_widget.addWidget(self.process_widget)
        self.central_widget.addWidget(self.notepad_widget)
        self.central_widget.addWidget(self.assistant_widget) # Add Assistant widget

        # --- Load Splitter State (UI Ratios) ---
        # This should work as intended based on the previous code analysis.
        # It's called AFTER widgets are added.
        self.load_splitter_state()

        self.status_bar = self.statusBar()

        try:
            self.clipboard = QGuiApplication.clipboard()
            self.clipboard.dataChanged.connect(self.on_clipboard_changed)
            self.on_clipboard_changed()
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

        # --- P2P Manager Setup ---
        self.p2p_thread = QThread(self)
        self.p2p_manager = P2PManager(self.settings)
        self.p2p_manager.moveToThread(self.p2p_thread)
        self.p2p_thread.started.connect(self.p2p_manager.start)
        self.p2p_manager.log_message.connect(self.log_status)
        self.p2p_manager.peer_status_changed.connect(self.update_peer_status_ui)
        self.p2p_manager.received_data.connect(self.handle_received_p2p_data)
        self.send_p2p_data_signal.connect(self.p2p_manager.send_to_all_peers)
        self.p2p_thread.start()

        # --- WebUI Worker Setup ---
        self.webui_thread = QThread(self)
        self.webui_worker = None # Worker created on demand
        # Connect the updated signal from AssistantWidget
        self.assistant_widget.send_conversation_signal.connect(self.handle_assistant_conversation)
        # Connect the updated signal to start the worker
        self.start_webui_chat_signal.connect(self.start_webui_chat_worker)

        self.create_tray_icon()

        # --- Auto Hide Setup ---
        self.auto_hide_timer = QTimer(self)
        self.auto_hide_timer.setInterval(200) # Check every 200ms
        self.auto_hide_timer.timeout.connect(self.check_mouse_position_for_auto_hide)
        self.is_mouse_near_edge = False # Track if mouse is currently near edge

        # Load auto-hide setting and apply initial state
        # Ensure auto_hide_action exists (created in create_tray_icon)
        self.auto_hide_action.setChecked(self.settings.value("window/autoHide", defaultValue=False, type=bool))
        # Use QTimer.singleShot to apply initial state slightly after __init__ completes
        # This avoids potential issues if toggle_auto_hide relies on fully initialized state
        QTimer.singleShot(0, lambda: self.toggle_auto_hide(self.auto_hide_action.isChecked()))

        self.position_as_sidebar()
        self.installEventFilter(self)
        self.update_assistant_availability() # Check if assistant can run initially
        logging.info("MainWindow initialized.")
        self.show() # Show window after initialization

    # --- Settings Loading/Handling ---
    def load_settings(self):
        logging.info("Loading settings...")
        # General
        default_notes_dir = os.path.join(QStandardPaths.writableLocation(QStandardPaths.AppDataLocation), SETTINGS_APP, "Notes")
        self.notes_directory = self.settings.value("notesDirectory", defaultValue=default_notes_dir)
        try:
            if not os.path.exists(self.notes_directory):
                os.makedirs(self.notes_directory)
                logging.info(f"Created notes directory: {self.notes_directory}")
        except Exception as e:
            logging.error(f"Failed to create notes directory {self.notes_directory}: {e}")
            QMessageBox.warning(self, "Error", f"Could not create notes directory: {self.notes_directory}")
            self.notes_directory = default_notes_dir
            try: os.makedirs(self.notes_directory, exist_ok=True)
            except: pass
        # WebUI
        self.webui_endpoint = self.settings.value("webui/endpoint", defaultValue="")
        self.webui_apikey = self.settings.value("webui/apikey", defaultValue="")
        self.webui_model = self.settings.value("webui/selected_model", defaultValue="")
        # P2P settings are loaded by P2PManager itself

    @Slot()
    def settings_updated(self):
        logging.info("Settings updated, reloading configuration...")
        old_notes_dir = self.notes_directory
        self.load_settings() # Reload general and WebUI settings
        if old_notes_dir != self.notes_directory:
            self.save_all_notes()
            self.load_notes()
        # Restart P2P manager
        if self.p2p_manager and self.p2p_thread.isRunning():
            logging.info("Restarting P2P Manager due to settings change...")
            self.p2p_manager.stop()
            QTimer.singleShot(500, self.p2p_manager.start)
        else:
             logging.warning("Cannot restart P2P Manager: Not running or not initialized.")
        # Update Assistant availability based on new settings
        self.update_assistant_availability()

    # --- Widget Creation Methods --- (No changes to clipboard/process/notepad)
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

        # --- Port Process Finder ---
        port_finder_group = QGroupBox("Find Process by Port")
        port_finder_layout = QHBoxLayout(port_finder_group)
        port_finder_layout.addWidget(QLabel("Port:"))
        self.port_search_input = QLineEdit()
        self.port_search_input.setPlaceholderText("Enter port number...")
        self.port_search_input.setFixedWidth(120) # Adjust width as needed
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
        add_tab_button.setFixedSize(40, 25) # Modified size
        add_tab_button.clicked.connect(lambda: self.add_new_notepad_tab())
        button_layout.addWidget(add_tab_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)
        layout.addWidget(self.notepad_tabs)
        return widget

    # --- Assistant Logic ---
    def update_assistant_availability(self):
        """Enable/disable assistant based on settings."""
        enabled = bool(self.webui_endpoint and self.webui_model)
        self.assistant_widget.setEnabled(enabled)
        if not enabled:
            self.assistant_widget.prompt_input.setPlaceholderText("Configure WebUI Endpoint and Model in Settings...")
            self.assistant_widget.clear_conversation()
        else:
            self.assistant_widget.prompt_input.setPlaceholderText("Enter your prompt...")
        logging.info(f"Assistant enabled status: {enabled}")

    @Slot(list) # Slot receives the list of messages
    def handle_assistant_conversation(self, messages):
        if not self.webui_endpoint or not self.webui_model:
            QMessageBox.warning(self, "Assistant Error", "WebUI Endpoint or Model not configured in Settings.")
            self.assistant_widget.on_stream_finished() # Re-enable buttons
            return
        if self.webui_worker and self.webui_thread.isRunning():
            logging.warning("Assistant is already processing a request.")
            # Optionally, you could queue the request or notify the user
            return
        # Emit signal to start the worker with the full conversation
        self.start_webui_chat_signal.emit(self.webui_endpoint, self.webui_apikey, self.webui_model, messages)

    # Slot receives endpoint, api_key, model, messages_list
    @Slot(str, str, str, list)
    def start_webui_chat_worker(self, endpoint, api_key, model, messages):
        # Stop previous worker if somehow still running (shouldn't happen with check above)
        if self.webui_worker and self.webui_thread.isRunning():
            logging.warning("Stopping lingering WebUI worker before starting new one.")
            self.webui_worker.stop()
            self.webui_thread.quit()
            self.webui_thread.wait(500)

        # Create and start new worker
        self.webui_worker = WebUIWorker(endpoint, api_key, model, messages)
        self.webui_worker.moveToThread(self.webui_thread)

        # Clear previous connections before making new ones
        try: self.webui_worker.stream_chunk.disconnect() 
        except RuntimeError: pass
        try: self.webui_worker.stream_finished.disconnect() 
        except RuntimeError: pass
        try: self.webui_worker.error.disconnect() 
        except RuntimeError: pass
        try: self.webui_worker.finished.disconnect() 
        except RuntimeError: pass

        # Connect signals for the new worker
        self.webui_worker.stream_chunk.connect(self.assistant_widget.handle_stream_chunk)
        self.webui_worker.stream_finished.connect(self.assistant_widget.on_stream_finished)
        self.webui_worker.error.connect(self.handle_webui_error)
        self.webui_worker.finished.connect(self.webui_thread.quit)
        self.webui_worker.finished.connect(self.webui_worker.deleteLater)
        self.webui_thread.started.connect(self.webui_worker.run_chat_stream)
        self.webui_thread.finished.connect(lambda: setattr(self, 'webui_worker', None)) # Clean up worker reference

        self.webui_thread.start()
        logging.info("WebUI chat worker started.")

    @Slot(str)
    def handle_webui_error(self, error_message):
        logging.error(f"WebUI Worker Error: {error_message}")
        QMessageBox.critical(self, "Assistant Error", f"An error occurred:\n{error_message}")
        # Ensure buttons are re-enabled even on error
        if self.assistant_widget:
            self.assistant_widget.on_stream_finished()

    # --- UI Positioning and Sizing ---
    def position_as_sidebar(self):
        try:
            screen = QGuiApplication.primaryScreen()
            if not screen: return
            available_geo = screen.availableGeometry()
            window_height = available_geo.height()
            self.setGeometry(available_geo.width() - SIDEBAR_WIDTH, available_geo.top(), SIDEBAR_WIDTH, window_height)
        except Exception as e:
            logging.error(f"Error positioning window: {e}")
            self.resize(SIDEBAR_WIDTH, 800) # Fallback size

    def load_splitter_state(self):
        try:
            state = self.settings.value("window/splitterState")
            if isinstance(state, QByteArray) and not state.isEmpty():
                if self.central_widget.restoreState(state):
                    logging.info("Restored splitter state.")
                    # Ensure sizes are reasonable after restore (optional but good practice)
                    self.adjust_splitter_sizes()
                    return
                else:
                    logging.warning("Failed to restore splitter state, using defaults.")
            else:
                logging.info("No saved splitter state found, using defaults.")
            # Default sizes if no state or restore failed
            self.set_default_splitter_sizes()
        except Exception as e:
            logging.error(f"Error loading splitter state: {e}")
            self.set_default_splitter_sizes()

    def set_default_splitter_sizes(self):
        total_height = self.central_widget.height()
        # Default: Give more space to Assistant and Notepad
        sizes = [
            int(total_height * 0.15),
            int(total_height * 0.15),
            int(total_height * 0.30),
            int(total_height * 0.40)
        ]
        self.central_widget.setSizes(sizes)
        logging.info(f"Set default splitter sizes: {sizes}")

    def adjust_splitter_sizes(self):
        """Adjusts splitter sizes to fit current window height if necessary."""
        sizes = self.central_widget.sizes()
        if len(sizes) != 4: # Should match number of widgets
            logging.warning("Splitter size count mismatch, resetting to defaults.")
            self.set_default_splitter_sizes()
            return

        total_height = self.central_widget.height()
        current_sum = sum(sizes)

        if total_height <= 0 or current_sum <= 0: return # Avoid division by zero or weird states

        # Scale sizes proportionally if total height changed significantly
        if abs(current_sum - total_height) > 10: # Threshold to avoid minor adjustments
            scale_factor = total_height / current_sum
            new_sizes = [max(10, int(s * scale_factor)) for s in sizes] # Ensure minimum size
            # Adjust last element to match total height exactly
            new_sizes[-1] = max(10, total_height - sum(new_sizes[:-1]))
            if sum(new_sizes) == total_height and all(s >= 10 for s in new_sizes):
                self.central_widget.setSizes(new_sizes)
                logging.debug(f"Adjusted splitter sizes proportionally: {new_sizes}")
            else:
                logging.warning("Proportional adjustment failed, using defaults.")
                self.set_default_splitter_sizes()

    def save_splitter_state(self):
        try:
            state = self.central_widget.saveState()
            self.settings.setValue("window/splitterState", state)
            logging.info("Saved splitter state.")
        except Exception as e:
            logging.error(f"Error saving splitter state: {e}")

    # --- Stylesheet --- (No changes)
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
        """)

    # --- Tray Icon Methods --- (Added connection for settings update)
    def create_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        # Simple blue circle icon
        pixmap = QPixmap(16, 16)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setBrush(Qt.blue)
        painter.drawEllipse(0, 0, 15, 15)
        painter.end()
        icon = QIcon(pixmap)
        self.tray_icon.setIcon(icon)
        self.tray_icon.setToolTip("SideBar Assistant - P2P")
        tray_menu = QMenu()
        show_action = QAction("Show", self, triggered=self.show_window)
        hide_action = QAction("Hide", self, triggered=self.hide_window)
        self.always_on_top_action = QAction("Always on Top", self, checkable=True, triggered=self.toggle_always_on_top)
        self.auto_hide_action = QAction("Auto Hide", self, checkable=True, triggered=self.toggle_auto_hide)
        settings_action = QAction("Settings...", self, triggered=self.open_settings_dialog)
        quit_action = QAction("Quit", self, triggered=self.quit_application)
        tray_menu.addAction(show_action); tray_menu.addAction(hide_action); tray_menu.addSeparator()
        tray_menu.addAction(self.always_on_top_action)
        tray_menu.addAction(self.auto_hide_action) # Added Auto Hide action
        tray_menu.addSeparator()
        tray_menu.addAction(settings_action); tray_menu.addAction(quit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.always_on_top_action.setChecked(bool(self.windowFlags() & Qt.WindowStaysOnTopHint))
        self.tray_icon.activated.connect(self.on_tray_activated)
        self.tray_icon.show()

    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger: self.toggle_window_visibility()

    def show_window(self):
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowStaysOnTopHint | (Qt.WindowStaysOnTopHint if self.always_on_top_action.isChecked() else Qt.WindowFlags()))
        self.showNormal()
        self.activateWindow()
        self.raise_()

    def hide_window(self):
        self.hide()

    def toggle_window_visibility(self):
        if self.isVisible(): self.hide()
        else: self.show_window()

    def toggle_always_on_top(self, checked):
        flags = self.windowFlags()
        if checked: self.setWindowFlags(flags | Qt.WindowStaysOnTopHint)
        else: self.setWindowFlags(flags & ~Qt.WindowStaysOnTopHint)
        if self.isVisible(): self.show()

    def open_settings_dialog(self):
        try:
            dialog = SettingsDialog(self.settings, self)
            # Connect the signal from the dialog to the main window's slot
            dialog.settings_updated_signal.connect(self.settings_updated)
            dialog.exec()
        except Exception as e:
            logging.error(f"Error opening settings dialog: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to open settings: {e}")

    def quit_application(self):
        logging.info("Quit requested from tray menu.")
        self.allow_close = True
        self.close()

    # --- Event Handling (Focus Out, Close) --- (Save splitter state on close)
    def eventFilter(self, obj, event):
        if event.type() == QEvent.WindowDeactivate or event.type() == QEvent.ApplicationDeactivate:
            if self.needs_sync:
                self.trigger_sync()
                self.needs_sync = False
        return super().eventFilter(obj, event)

    def closeEvent(self, event: QCloseEvent):
        if self.allow_close:
            logging.info("Closing application...")
            self.save_splitter_state() # Ensure splitter state is saved
            self.save_all_notes()
            if self.p2p_manager: self.p2p_manager.stop()
            if self.p2p_thread.isRunning():
                self.p2p_thread.quit()
                self.p2p_thread.wait(1000)
            # Stop WebUI worker if running
            if self.webui_worker and self.webui_thread.isRunning():
                 self.webui_worker.stop()
                 self.webui_thread.quit()
                 self.webui_thread.wait(1000)
            self.tray_icon.hide()
            logging.info("Application closed.")
            event.accept()
        else:
            logging.debug("Close event ignored, hiding window instead.")
            event.ignore()
            self.hide()

    # --- Clipboard Methods --- (No changes)
    def on_clipboard_changed(self):
        if not self.monitoring_clipboard: return
        try:
            mime_data = self.clipboard.mimeData()
            if not mime_data: return
            new_item_data = None; data_type = None
            current_text = self.clipboard.text()
            current_pixmap = self.clipboard.pixmap()
            if mime_data.hasImage() and not current_pixmap.isNull():
                is_new = True
                if self.clipboard_history:
                    last_item = self.clipboard_history[0]
                    if last_item.data_type == 'image' and self.pixmaps_equal(last_item.data, current_pixmap): is_new = False
                if is_new: new_item_data = current_pixmap; data_type = 'image'
            elif mime_data.hasText() and current_text:
                is_new = True
                if self.clipboard_history:
                    last_item = self.clipboard_history[0]
                    if last_item.data_type == 'text' and last_item.data == current_text: is_new = False
                if is_new: new_item_data = current_text; data_type = 'text'
            if new_item_data and data_type:
                new_item = ClipboardItem(data_type, new_item_data)
                self.clipboard_history.insert(0, new_item)
                if len(self.clipboard_history) > MAX_CLIPBOARD_HISTORY: self.clipboard_history.pop()
                self.update_clipboard_list_ui()
                self.schedule_sync("clipboard")
        except Exception as e:
            logging.error(f"Error processing clipboard change: {e}", exc_info=True)

    def pixmaps_equal(self, p1, p2):
        try:
            if p1.isNull() and p2.isNull(): return True
            if p1.isNull() or p2.isNull(): return False
            if p1.cacheKey() == p2.cacheKey(): return True
            return p1.toImage() == p2.toImage()
        except Exception as e:
            logging.error(f"Error comparing pixmaps: {e}")
            return False

    def update_clipboard_list_ui(self):
        try:
            self.clipboard_list.clear()
            for i, item in enumerate(self.clipboard_history):
                list_item = QListWidgetItem()
                if item.data_type == 'text':
                    preview = item.data.split('\n')[0][:50] + ('...' if len(item.data) > 50 else '')
                    list_item.setText(f"{i+1}. {preview}")
                elif item.data_type == 'image':
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
        if not (0 <= index < len(self.clipboard_history)): return
        history_item = self.clipboard_history[index]
        try:
            self.monitoring_clipboard = False
            self.clipboard.clear()
            mime_data = QMimeData()
            if history_item.data_type == 'text': mime_data.setText(history_item.data)
            elif history_item.data_type == 'image':
                mime_data.setImageData(history_item.data.toImage())
                # Setting pixmap might be redundant if mime data is set, but doesn't hurt
                self.clipboard.setPixmap(history_item.data)
            self.clipboard.setMimeData(mime_data)
            self.log_status(f"Item {index+1} copied to clipboard.", 3000)
        except Exception as e:
            logging.error(f"Error copying item {index+1} to clipboard: {e}", exc_info=True)
            QMessageBox.warning(self, "Error", f"Failed to copy item to clipboard: {e}")
        finally:
            # Delay re-enabling monitoring slightly
            QTimer.singleShot(150, lambda: setattr(self, 'monitoring_clipboard', True))

    def setup_clipboard_shortcuts(self):
        try:
            for i in range(10):
                shortcut = QShortcut(QKeySequence(f"Ctrl+{ (i + 1) % 10 }"), self)
                shortcut.activated.connect(lambda index=i: self.copy_item_to_clipboard(index))
                setattr(self, f"shortcut_ctrl_{i}", shortcut)
        except Exception as e:
            logging.error(f"Failed to setup clipboard shortcuts: {e}", exc_info=True)

    # --- Process Manager Methods --- (No changes)
    def update_process_list(self):
        try:
            new_processes = {}
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    new_processes[proc.info['pid']] = proc.info['name']
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
            # Sort by name, case-insensitive
            sorted_processes = sorted(self.current_processes.items(), key=lambda item: item[1].lower())
            for pid, name in sorted_processes:
                if not search or search in str(pid) or search in name.lower():
                    item = QListWidgetItem(f"{pid}: {name}")
                    item.setData(Qt.UserRole, pid)
                    self.process_list.addItem(item)
                    if pid in selected_pids: item.setSelected(True)
        except Exception as e:
            logging.error(f"Error filtering process list UI: {e}", exc_info=True)

    def kill_selected_processes(self):
        try:
            items = self.process_list.selectedItems()
            if not items: return
            to_kill = [] ; critical = False ; details = []
            for item in items:
                pid = item.data(Qt.UserRole)
                name = self.current_processes.get(pid, "Unknown Process")
                is_crit = any(c.lower() in name.lower() for c in CRITICAL_PROCESSES)
                to_kill.append({"pid": pid, "name": name})
                details.append(f"- {name} ({pid}){ ' [CRITICAL]' if is_crit else '' }")
                if is_crit: critical = True
            msg = f"Terminate the following {len(to_kill)} process(es)?\n\n" + "\n".join(details)
            if critical:
                msg += "\n\nWARNING: One or more selected processes appear critical... Terminating them may cause system instability or data loss."
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
                            logging.info(f"Terminated process {p_info['name']} ({p_info['pid']})")
                        except psutil.TimeoutExpired:
                            logging.warning(f"Process {p_info['name']} ({p_info['pid']}) did not terminate gracefully, killing forcefully.")
                            p.kill()
                            p.wait(timeout=0.2)
                            killed += 1
                            logging.info(f"Killed process {p_info['name']} ({p_info['pid']})")
                    except psutil.NoSuchProcess:
                        logging.info(f"Process {p_info['name']} ({p_info['pid']}) already exited.")
                        killed += 1
                    except psutil.AccessDenied:
                        logging.warning(f"Access denied trying to terminate {p_info['name']} ({p_info['pid']}).")
                        failed += 1
                    except Exception as e:
                        logging.error(f"Failed to terminate/kill {p_info['name']} ({p_info['pid']}): {e}", exc_info=True)
                        failed += 1
                self.log_status(f"Process termination complete. Killed/Exited: {killed}, Failed: {failed}.", 5000)
                self.update_process_list()
        except Exception as e:
            logging.error(f"Error during kill process operation: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"An unexpected error occurred during process termination: {e}")

    # --- Port Process Finder Logic ---
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
                # Check for listening ports
                if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port:
                    if conn.pid:
                        found_pids.add(conn.pid)
                # Optionally check for established connections involving the port
                # elif conn.status == psutil.CONN_ESTABLISHED and conn.pid:
                #     if conn.laddr.port == port or (hasattr(conn.raddr, 'port') and conn.raddr.port == port):
                #         found_pids.add(conn.pid)

            if not found_pids:
                QMessageBox.information(self, "Not Found", f"No process found using port {port}.")
                return

            self.process_list.clearSelection() # Clear previous selection
            items_to_select = []
            for pid in found_pids:
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    process_info.append(f"- PID: {pid}, Name: {name}")
                    # Find the item in the list and select it
                    for i in range(self.process_list.count()):
                        item = self.process_list.item(i)
                        if item and item.data(Qt.UserRole) == pid:
                            items_to_select.append(item)
                            break # Found the item for this PID
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_info.append(f"- PID: {pid}, Name: (Could not retrieve name)")

            # Select found items
            for item in items_to_select:
                item.setSelected(True)
                self.process_list.scrollToItem(item, QAbstractItemView.PositionAtCenter)

            QMessageBox.information(self, "Process Found",
                                      f"Found process(es) using port {port}:\n\n" +
                                      "\n".join(process_info) + "\n\nHighlighted in the list.")

        except psutil.AccessDenied:
            logging.error("Access denied while checking network connections.")
            QMessageBox.critical(self, "Access Denied", "Could not retrieve network connection information. Try running as administrator/root.")
        except Exception as e:
            logging.error(f"Error finding process by port {port}: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")

    # --- Notepad Methods --- (No changes)
    def on_notepad_tab_changed(self, index):
        self.save_current_note_if_changed() # Save previous tab if needed

    def on_notepad_text_changed(self):
        index = self.notepad_tabs.currentIndex()
        if index != -1:
            self.notes_changed[index] = True
            self.mark_tab_unsaved(index, True)
            self.note_save_timer.start() # Start/restart save timer

    def mark_tab_unsaved(self, index, unsaved):
        try:
            tab_bar = self.notepad_tabs.tabBar()
            tab_text = self.notepad_tabs.tabText(index)
            # Use a property to avoid modifying the actual name stored elsewhere
            tab_bar.setTabData(index, unsaved)
            # Update visual indicator (e.g., italic or asterisk)
            if unsaved:
                if not tab_text.endswith(" *"): self.notepad_tabs.setTabText(index, tab_text + " *")
            else:
                if tab_text.endswith(" *"): self.notepad_tabs.setTabText(index, tab_text[:-2])
            # Force style update for custom properties
            style = tab_bar.style()
            style.unpolish(tab_bar)
            style.polish(tab_bar)
        except Exception as e:
            logging.error(f"Error marking tab unsaved status: {e}")

    def save_current_note_if_changed(self):
        # This is triggered by timer or tab change
        for index, changed in list(self.notes_changed.items()):
            if changed and index != self.notepad_tabs.currentIndex(): # Save inactive tabs that changed
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
        if not (0 <= index < self.notepad_tabs.count()): return False
        widget = self.notepad_tabs.widget(index)
        tab_name = self.notepad_tabs.tabText(index)
        if tab_name.endswith(" *"): tab_name = tab_name[:-2]
        if isinstance(widget, QTextEdit):
            filepath = self.get_note_filepath(tab_name)
            content = widget.toPlainText()
            timestamp = time.time()
            try:
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                with open(filepath, 'w', encoding='utf-8') as f: f.write(content)
                widget.setProperty("timestamp", timestamp)
                if mark_saved:
                    self.notes_changed[index] = False
                    self.mark_tab_unsaved(index, False)
                logging.info(f"Saved note '{tab_name}' to {filepath}")
                self.schedule_sync("notepad_update", {"name": tab_name, "content": content, "timestamp": timestamp})
                return True
            except Exception as e:
                logging.error(f"Error saving note '{tab_name}' to {filepath}: {e}", exc_info=True)
                QMessageBox.warning(self, "Save Error", f"Failed to save note '{tab_name}':\n{e}")
                return False
        return False

    def get_note_filepath(self, note_name):
        # Sanitize note name for filename (basic example)
        safe_filename = re.sub(r'[\/*?"<>|]', "_", note_name) + ".txt"
        return os.path.join(self.notes_directory, safe_filename)

    def load_notes(self):
        logging.info(f"Loading notes from: {self.notes_directory}")
        try:
            # Clear existing tabs before loading
            while self.notepad_tabs.count() > 0:
                # Don't check for unsaved changes here, assume saved on close/reload
                self.notepad_tabs.removeTab(0)
            self.notes_changed.clear()

            if not os.path.isdir(self.notes_directory):
                logging.warning(f"Notes directory not found: {self.notes_directory}. Creating initial tab.")
                return self.add_initial_notepad_tab()

            loaded_count = 0
            for filename in sorted(os.listdir(self.notes_directory)):
                if filename.endswith(".txt"):
                    filepath = os.path.join(self.notes_directory, filename)
                    tab_name = os.path.splitext(filename)[0]
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f: content = f.read()
                        # Get timestamp from file metadata as fallback
                        timestamp = os.path.getmtime(filepath)
                        self.add_new_notepad_tab(name=tab_name, content=content, timestamp=timestamp)
                        loaded_count += 1
                    except Exception as e:
                        logging.error(f"Error loading note '{filename}': {e}")

            if loaded_count == 0: self.add_initial_notepad_tab()
            logging.info(f"Loaded {loaded_count} notes.")
        except Exception as e:
            logging.error(f"Critical error loading notes: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to load notes: {e}")
            self.add_initial_notepad_tab()

    def add_initial_notepad_tab(self):
        if self.notepad_tabs.count() == 0: self.add_new_notepad_tab(name="Note 1", content="")

    def add_new_notepad_tab(self, name=None, content="", timestamp=None):
        try:
            if name is None:
                i = 1
                while True:
                    potential_name = f"New Note {i}"
                    if not os.path.exists(self.get_note_filepath(potential_name)): name = potential_name; break
                    i += 1
                    if i > 1000: name = f"Untitled_{int(time.time())}"; break # Fallback for too many notes

            text_edit = QTextEdit()
            text_edit.setPlainText(content)
            text_edit.setProperty("timestamp", timestamp or time.time())
            index = self.notepad_tabs.addTab(text_edit, name)
            self.notepad_tabs.setCurrentIndex(index)
            self.notes_changed[index] = False # New tab is initially unchanged
            text_edit.textChanged.connect(self.on_notepad_text_changed)
            self.mark_tab_unsaved(index, False)
        except Exception as e:
            logging.error(f"Error adding new notepad tab: {e}", exc_info=True)
            QMessageBox.warning(self, "Error", f"Failed to add new note tab: {e}")

    def rename_current_notepad_tab(self):
        idx = self.notepad_tabs.currentIndex()
        if idx == -1: return
        old_name_display = self.notepad_tabs.tabText(idx)
        was_unsaved = old_name_display.endswith(" *")
        old_name_actual = old_name_display[:-2] if was_unsaved else old_name_display
        old_filepath = self.get_note_filepath(old_name_actual)

        new_name_actual, ok = QInputDialog.getText(self, "Rename Note", "New name:", QLineEdit.Normal, old_name_actual)
        if ok and new_name_actual and new_name_actual != old_name_actual:
            new_filepath = self.get_note_filepath(new_name_actual)
            if os.path.exists(new_filepath):
                QMessageBox.warning(self, "Rename Failed", f"A note named '{new_name_actual}' already exists.")
                return
            try:
                current_widget = self.notepad_tabs.widget(idx)
                if isinstance(current_widget, QTextEdit):
                    # Save content to the *new* file name immediately
                    content_to_save = current_widget.toPlainText()
                    os.makedirs(os.path.dirname(new_filepath), exist_ok=True)
                    with open(new_filepath, 'w', encoding='utf-8') as f: f.write(content_to_save)
                    logging.info(f"Saved content to new file '{os.path.basename(new_filepath)}' during rename.")

                    # Remove the old file if it exists and name changed
                    if os.path.exists(old_filepath) and old_filepath != new_filepath:
                        try:
                            os.remove(old_filepath)
                            logging.info(f"Removed old note file '{os.path.basename(old_filepath)}'.")
                        except Exception as remove_err:
                            logging.warning(f"Failed to remove old note file '{os.path.basename(old_filepath)}': {remove_err}")

                    # Update tab text
                    new_name_display = new_name_actual + (" *" if was_unsaved else "")
                    self.notepad_tabs.setTabText(idx, new_name_display)
                    # Mark as saved since we just wrote the file
                    self.notes_changed[idx] = False
                    self.mark_tab_unsaved(idx, False)
                    logging.info(f"Renamed note tab from '{old_name_actual}' to '{new_name_actual}'.")
                    # Trigger sync for rename event
                    self.schedule_sync("notepad_rename", {"old_name": old_name_actual, "new_name": new_name_actual})
                else:
                    logging.warning("Cannot save content during rename: Widget is not QTextEdit.")
            except Exception as e:
                logging.error(f"Error renaming note '{old_name_actual}' to '{new_name_actual}': {e}", exc_info=True)
                QMessageBox.warning(self, "Rename Error", f"Failed to rename note: {e}")
                # Revert tab text if rename failed
                self.notepad_tabs.setTabText(idx, old_name_display)

    def close_notepad_tab(self, index):
        if not (0 <= index < self.notepad_tabs.count()): return
        widget = self.notepad_tabs.widget(index)
        tab_name_display = self.notepad_tabs.tabText(index)
        tab_name_actual = tab_name_display[:-2] if tab_name_display.endswith(" *") else tab_name_display
        is_unsaved = self.notes_changed.get(index, False)

        if is_unsaved:
            reply = QMessageBox.question(self, "Unsaved Changes",
                                         f"Save changes to '{tab_name_actual}'?",
                                         QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel, QMessageBox.Save)
            if reply == QMessageBox.Cancel: return
            elif reply == QMessageBox.Save:
                if not self.save_note(index, mark_saved=True): return # Abort close if save fails

        try:
            filepath = self.get_note_filepath(tab_name_actual)
            self.notepad_tabs.removeTab(index)
            # Clean up notes_changed dictionary
            if index in self.notes_changed: del self.notes_changed[index]
            new_notes_changed = {}
            for old_idx, changed_status in self.notes_changed.items():
                if old_idx > index: new_notes_changed[old_idx - 1] = changed_status
                elif old_idx < index: new_notes_changed[old_idx] = changed_status
            self.notes_changed = new_notes_changed

            logging.info(f"Closed note tab '{tab_name_actual}'.")
            # Optionally delete the file from disk
            # if os.path.exists(filepath):
            #     try: os.remove(filepath); logging.info(f"Deleted note file: {filepath}")
            #     except Exception as e: logging.error(f"Failed to delete note file {filepath}: {e}")

            self.schedule_sync("notepad_delete", {"name": tab_name_actual})
            if self.notepad_tabs.count() == 0: self.add_initial_notepad_tab()
        except Exception as e:
            logging.error(f"Error closing notepad tab {index}: {e}", exc_info=True)

    def show_notepad_tab_context_menu(self, position):
        try:
            tab_bar = self.notepad_tabs.tabBar()
            index = tab_bar.tabAt(position)
            if index != -1:
                menu = QMenu()
                rename_action = menu.addAction("Rename")
                close_action = menu.addAction("Close")
                action = menu.exec(tab_bar.mapToGlobal(position))
                if action == rename_action: self.rename_current_notepad_tab() # Uses current index, ensure it matches clicked index
                elif action == close_action: self.close_notepad_tab(index)
        except Exception as e:
            logging.error(f"Error showing notepad context menu: {e}", exc_info=True)

    # --- P2P Sync Logic --- (No changes)
    def schedule_sync(self, data_type, details=None):
        self.needs_sync = True
        logging.debug(f"Sync scheduled for {data_type}. Details: {details}")

    def trigger_sync(self):
        if not self.p2p_manager or not self.p2p_manager.p2p_enabled: return
        logging.info("Focus lost, triggering P2P sync...")
        try:
            clipboard_data = [item.to_dict() for item in self.clipboard_history if item.to_dict() is not None]
            notepad_data = {}
            for i in range(self.notepad_tabs.count()):
                widget = self.notepad_tabs.widget(i)
                tab_name = self.notepad_tabs.tabText(i)
                if tab_name.endswith(" *"): tab_name = tab_name[:-2]
                if isinstance(widget, QTextEdit):
                    timestamp = widget.property("timestamp") or time.time()
                    notepad_data[tab_name] = {"content": widget.toPlainText(), "timestamp": timestamp}
            sync_payload = {
                "type": "SYNC_DATA", "clipboard": clipboard_data,
                "notepad": notepad_data, "sender_timestamp": time.time()
            }
            self.send_p2p_data_signal.emit(sync_payload)
            self.log_status("Sync data sent to P2P manager.", 3000)
        except Exception as e:
            logging.error(f"Error preparing or triggering sync: {e}", exc_info=True)
            self.log_status(f"Sync Error: {e}", 5000)

    @Slot(dict)
    def handle_received_p2p_data(self, data):
        if not self.p2p_manager or not self.p2p_manager.p2p_enabled: return
        data_type = data.get("type")
        logging.info(f"Handling received P2P data of type: {data_type}")
        try:
            if data_type == "SYNC_DATA":
                remote_clipboard = data.get("clipboard", [])
                self.sync_clipboard_history(remote_clipboard)
                remote_notepad = data.get("notepad", {})
                self.sync_notepad_content(remote_notepad)
                self.log_status("Sync received and processed.", 3000)
            elif data_type == "NOTEPAD_RENAME":
                old_name = data.get("old_name"); new_name = data.get("new_name")
                if old_name and new_name: self.handle_remote_notepad_rename(old_name, new_name)
            elif data_type == "NOTEPAD_DELETE":
                 name_to_delete = data.get("name")
                 if name_to_delete: self.handle_remote_notepad_delete(name_to_delete)
        except Exception as e:
            logging.error(f"Error handling received P2P data: {e}", exc_info=True)
            self.log_status(f"Sync Process Error: {e}", 5000)

    def sync_clipboard_history(self, remote_history_dicts):
        logging.debug(f"Syncing clipboard history. Remote count: {len(remote_history_dicts)}")
        local_timestamps = {item.timestamp: item for item in self.clipboard_history}
        new_items_added = False
        for item_dict in remote_history_dicts:
            remote_item = ClipboardItem.from_dict(item_dict)
            if remote_item:
                # Check if timestamp exists, and if content is different (for potential edits, though unlikely with clipboard)
                if remote_item.timestamp not in local_timestamps:
                    self.clipboard_history.append(remote_item)
                    new_items_added = True
                    logging.debug(f"Added remote clipboard item (ts: {remote_item.timestamp})")
            else: logging.warning("Failed to create ClipboardItem from remote dict.")
        if new_items_added:
            self.clipboard_history.sort(key=lambda x: x.timestamp, reverse=True)
            if len(self.clipboard_history) > MAX_CLIPBOARD_HISTORY:
                self.clipboard_history = self.clipboard_history[:MAX_CLIPBOARD_HISTORY]
            logging.info("Clipboard history updated from remote sync.")
            self.update_clipboard_list_ui()

    def sync_notepad_content(self, remote_notepad_data):
        logging.debug(f"Syncing notepad content. Remote notes count: {len(remote_notepad_data)}")
        local_tabs = {}
        for i in range(self.notepad_tabs.count()):
            tab_name = self.notepad_tabs.tabText(i)
            if tab_name.endswith(" *"): tab_name = tab_name[:-2]
            widget = self.notepad_tabs.widget(i)
            if isinstance(widget, QTextEdit): local_tabs[tab_name] = {"widget": widget, "index": i}

        tabs_updated = False; tabs_added = False; tabs_to_remove_indices = []

        for remote_name, remote_data in remote_notepad_data.items():
            remote_content = remote_data.get("content", ""); remote_timestamp = remote_data.get("timestamp", 0)
            if remote_name in local_tabs:
                local_info = local_tabs[remote_name]
                local_widget = local_info["widget"]
                local_timestamp = local_widget.property("timestamp") or 0
                local_index = local_info["index"]
                is_local_unsaved = self.notes_changed.get(local_index, False)

                # Conflict Resolution: Remote wins if newer, unless local is unsaved and newer
                if remote_timestamp > local_timestamp and not (is_local_unsaved and local_timestamp > remote_timestamp):
                    current_local_content = local_widget.toPlainText()
                    if current_local_content != remote_content:
                        logging.info(f"Updating local note '{remote_name}' from remote (ts: {remote_timestamp} > {local_timestamp})")
                        local_widget.blockSignals(True)
                        local_widget.setPlainText(remote_content)
                        local_widget.setProperty("timestamp", remote_timestamp)
                        local_widget.blockSignals(False)
                        self.mark_tab_unsaved(local_index, False) # Mark as saved after remote update
                        self.notes_changed[local_index] = False
                        tabs_updated = True
                elif is_local_unsaved and local_timestamp > remote_timestamp:
                    logging.info(f"Keeping local unsaved changes for '{remote_name}' (ts: {local_timestamp} > {remote_timestamp})")
                # Remove from local_tabs dict so it's not deleted later
                del local_tabs[remote_name]
            else:
                # New note from remote
                logging.info(f"Adding new note '{remote_name}' from remote sync (ts: {remote_timestamp})")
                self.add_new_notepad_tab(name=remote_name, content=remote_content, timestamp=remote_timestamp)
                tabs_added = True

        # Any remaining items in local_tabs were not in the remote data
        for local_name_to_delete, local_info in local_tabs.items():
            local_index = local_info["index"]
            logging.info(f"Removing local note '{local_name_to_delete}' as it's missing from remote sync.")
            tabs_to_remove_indices.append(local_index)

        if tabs_to_remove_indices:
            # Remove tabs in reverse order to avoid index issues
            for index in sorted(tabs_to_remove_indices, reverse=True):
                try:
                    self.notepad_tabs.removeTab(index)
                    # Clean up notes_changed dictionary
                    if index in self.notes_changed: del self.notes_changed[index]
                    new_notes_changed = {}
                    for old_idx, changed_status in self.notes_changed.items():
                        if old_idx > index: new_notes_changed[old_idx - 1] = changed_status
                        elif old_idx < index: new_notes_changed[old_idx] = changed_status
                    self.notes_changed = new_notes_changed
                except Exception as e:
                    logging.error(f"Error removing synced-deleted tab at index {index}: {e}")
            tabs_updated = True # Indicate UI changed

        if tabs_updated or tabs_added:
            logging.info("Notepad content updated from remote sync.")
            if self.notepad_tabs.count() == 0: self.add_initial_notepad_tab()

    def handle_remote_notepad_rename(self, old_name, new_name):
        logging.info(f"Handling remote rename: '{old_name}' -> '{new_name}'.")
        found_index = -1
        for i in range(self.notepad_tabs.count()):
            tab_name = self.notepad_tabs.tabText(i)
            if tab_name.endswith(" *"): tab_name = tab_name[:-2]
            if tab_name == old_name: found_index = i; break

        if found_index != -1:
            # Check if the new name already exists locally (excluding the tab being renamed)
            new_name_exists = False
            for i in range(self.notepad_tabs.count()):
                 if i == found_index: continue
                 tab_name = self.notepad_tabs.tabText(i)
                 if tab_name.endswith(" *"): tab_name = tab_name[:-2]
                 if tab_name == new_name: new_name_exists = True; break

            if new_name_exists:
                 logging.warning(f"Cannot apply remote rename: Target name '{new_name}' already exists locally.")
                 # Potential conflict: Maybe create a copy or notify user?
                 return

            was_unsaved = self.notepad_tabs.tabText(found_index).endswith(" *")
            new_display_name = new_name + (" *" if was_unsaved else "")
            self.notepad_tabs.setTabText(found_index, new_display_name)

            # Rename the underlying file
            old_filepath = self.get_note_filepath(old_name)
            new_filepath = self.get_note_filepath(new_name)
            try:
                if os.path.exists(old_filepath):
                    os.rename(old_filepath, new_filepath)
                    logging.info(f"Renamed note file: '{os.path.basename(old_filepath)}' -> '{os.path.basename(new_filepath)}'")
                else:
                    # If old file doesn't exist, maybe save current content to new file?
                    widget = self.notepad_tabs.widget(found_index)
                    if isinstance(widget, QTextEdit):
                        content = widget.toPlainText()
                        with open(new_filepath, 'w', encoding='utf-8') as f: f.write(content)
                        logging.info(f"Saved current content to new file '{os.path.basename(new_filepath)}' during remote rename.")
            except Exception as e:
                logging.error(f"Error renaming note file during remote sync: {e}")
                # Revert tab text if file rename failed?
                # self.notepad_tabs.setTabText(found_index, self.notepad_tabs.tabText(found_index)) # Revert?
        else:
            logging.warning(f"Cannot apply remote rename: Note '{old_name}' not found locally.")

    def handle_remote_notepad_delete(self, name_to_delete):
        logging.info(f"Handling remote delete for note: '{name_to_delete}'.")
        found_index = -1
        for i in range(self.notepad_tabs.count()):
            tab_name = self.notepad_tabs.tabText(i)
            if tab_name.endswith(" *"): tab_name = tab_name[:-2]
            if tab_name == name_to_delete: found_index = i; break

        if found_index != -1:
            # Close the tab without prompting (as it was deleted remotely)
            try:
                self.notepad_tabs.removeTab(found_index)
                # Clean up notes_changed dictionary
                if found_index in self.notes_changed: del self.notes_changed[found_index]
                new_notes_changed = {}
                for old_idx, changed_status in self.notes_changed.items():
                    if old_idx > found_index: new_notes_changed[old_idx - 1] = changed_status
                    elif old_idx < found_index: new_notes_changed[old_idx] = changed_status
                self.notes_changed = new_notes_changed
                logging.info(f"Removed local note tab '{name_to_delete}' due to remote delete.")
                # Optionally delete the local file as well
                filepath = self.get_note_filepath(name_to_delete)
                if os.path.exists(filepath):
                    try: os.remove(filepath); logging.info(f"Deleted local file: {filepath}")
                    except Exception as e: logging.error(f"Failed to delete local file {filepath}: {e}")
                if self.notepad_tabs.count() == 0: self.add_initial_notepad_tab()
            except Exception as e:
                logging.error(f"Error removing tab during remote delete sync: {e}")
        else:
            logging.warning(f"Cannot apply remote delete: Note '{name_to_delete}' not found locally.")

    # --- Status Bar --- (No changes)
    @Slot(str, int)
    def log_status(self, message, timeout=0):
        try:
            self.status_bar.showMessage(message, timeout)
            logging.debug(f"Status Bar: {message}")
        except Exception as e:
            logging.error(f"Error showing status message: {e}")

    @Slot(str, int, str)
    def update_peer_status_ui(self, address, port, status):
        # This could update a dedicated UI element in the future
        logging.info(f"Peer Status Update: {address}:{port} -> {status}")
        self.log_status(f"Peer {address}:{port} is now {status}", 3000)

    # --- Port Process Finder Logic ---
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
                if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port:
                    if conn.pid:
                        found_pids.add(conn.pid)
                # Also check established connections (optional, depending on need)
                # elif conn.status == psutil.CONN_ESTABLISHED and (conn.laddr.port == port or conn.raddr.port == port):
                #     if conn.pid:
                #         found_pids.add(conn.pid)

            if not found_pids:
                QMessageBox.information(self, "Not Found", f"No process found listening on port {port}.")
                return

            self.process_list.clearSelection() # Clear previous selection
            items_to_select = []
            for pid in found_pids:
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    process_info.append(f"- PID: {pid}, Name: {name}")
                    # Find the item in the list and select it
                    for i in range(self.process_list.count()):
                        item = self.process_list.item(i)
                        if item.data(Qt.UserRole) == pid:
                            items_to_select.append(item)
                            break # Found the item for this PID
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_info.append(f"- PID: {pid}, Name: (Could not retrieve name)")

            # Select found items
            for item in items_to_select:
                item.setSelected(True)
                self.process_list.scrollToItem(item, QAbstractItemView.PositionAtCenter)

            QMessageBox.information(self, "Process Found",
                                      f"Found process(es) using port {port}:\n\n" +
                                      "\n".join(process_info) + "\n\nHighlighted in the list.")

        except psutil.AccessDenied:
            logging.error("Access denied while checking network connections.")
            QMessageBox.critical(self, "Access Denied", "Could not retrieve network connection information. Try running as administrator/root.")
        except Exception as e:
            logging.error(f"Error finding process by port {port}: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")


    # --- Auto Hide Methods ---
    @Slot(bool)
    def toggle_auto_hide(self, checked):
        logging.info(f"Auto Hide toggled: {checked}")
        self.settings.setValue("window/autoHide", checked)
        if checked:
            self.auto_hide_timer.start()
            # Check immediately if we should hide
            QTimer.singleShot(100, self.check_mouse_position_for_auto_hide)
        else:
            self.auto_hide_timer.stop()
            # Ensure window is visible if auto-hide is turned off
            if not self.isVisible():
                self.show_window()

    @Slot()
    def check_mouse_position_for_auto_hide(self):
        if not self.auto_hide_action.isChecked():
            return # Do nothing if auto-hide is disabled

        try:
            screen_width, screen_height = pyautogui.size()
            mouse_x, mouse_y = pyautogui.position()

            edge_threshold = 5 # Pixels from the edge to trigger show

            is_near_right_edge = mouse_x >= (screen_width - edge_threshold)

            if is_near_right_edge:
                if not self.isVisible():
                    logging.debug("Mouse near right edge, showing window.")
                    self.show_window()
                self.is_mouse_near_edge = True
            else: # Mouse is NOT near the right edge
                # Hide if window is visible but inactive and mouse is outside window bounds
                if self.isVisible() and not self.isActiveWindow():
                    window_rect = self.geometry()
                    # mapFromGlobal requires QPoint
                    if not window_rect.contains(self.mapFromGlobal(QPoint(mouse_x, mouse_y))):
                         logging.debug("Mouse not near edge, window inactive, mouse outside window -> hiding.")
                         self.hide_window()
                self.is_mouse_near_edge = False # Still reset flag

        except Exception as e:
            # PyAutoGUI might fail on some systems (e.g., Wayland without specific setup)
            logging.warning(f"Could not check mouse position for auto-hide: {e}")
            # Disable auto-hide if pyautogui fails consistently?
            # self.auto_hide_action.setChecked(False)
            # self.auto_hide_timer.stop()
            # QMessageBox.warning(self, "Auto-Hide Error", "Failed to monitor mouse position. Auto-hide disabled.")
            pass # For now, just log the warning and continue


# --- Main Execution ---
if __name__ == "__main__":
    # Ensure AppData directory exists for settings
    try:
        app_data_path = QStandardPaths.writableLocation(QStandardPaths.AppDataLocation)
        if not os.path.exists(app_data_path):
            os.makedirs(app_data_path)
    except Exception as e:
        logging.critical(f"Failed to create AppData directory: {e}")

    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False) # Keep running in tray

    try:
        window = MainWindow()
        # window.show() # Show handled in MainWindow.__init__
        logging.info("Application starting...")
        exit_code = app.exec()
        logging.info(f"Application exited with code {exit_code}.")
        sys.exit(exit_code)
    except Exception as e:
        logging.critical(f"Unhandled exception in main execution: {e}", exc_info=True)
        try:
            # Attempt to show a message box even if GUI loop failed
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Critical)
            msg_box.setWindowTitle("Fatal Error")
            msg_box.setText(f"An unhandled error occurred:\n\n{e}\n\nSee log file for details.")
            msg_box.exec()
        except: pass # Ignore errors during error reporting
        sys.exit(1)
