# main_2_final_v3.py
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

# pyautogui is removed as QCursor will be used for mouse position

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QTabWidget, QLabel,
    QTextEdit, QListWidget, QPushButton, QLineEdit, QHBoxLayout, QSplitter,
    QListWidgetItem, QMessageBox, QInputDialog, QFileDialog, QAbstractItemView,
    QSystemTrayIcon, QMenu, QDialog, QFormLayout, QDialogButtonBox,
    QGroupBox, QTabBar, QCheckBox, QComboBox, QPlainTextEdit
)
from PySide6.QtCore import (
    Qt, QTimer, QSettings, QSize, QMimeData, QDir, QStandardPaths, QRect,
    QByteArray, QBuffer, QIODevice, Signal, QObject, QThread, Slot, QEvent,
    QMetaObject, Q_ARG, QPoint # Added QPoint, QMetaObject, Q_ARG
)
from PySide6.QtGui import (
    QClipboard, QPixmap, QImage, QAction, QIcon, QGuiApplication, QCursor, # Added QCursor
    QShortcut, QKeySequence, QScreen, QCloseEvent, QTextCursor, QPainter
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

# --- P2P Peer Class --- (No changes from original)
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

# --- Settings Dialog --- (No changes from original)
class SettingsDialog(QDialog):
    settings_updated_signal = Signal()

    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("Settings")
        self.setModal(True)
        self.setMinimumWidth(500)
        main_layout = QVBoxLayout(self)
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
        button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.save_and_close)
        button_box.rejected.connect(self.reject)
        main_layout.addWidget(button_box)
        self.load_settings_values()

    def load_settings_values(self):
        default_notes_dir = os.path.join(QStandardPaths.writableLocation(QStandardPaths.AppDataLocation), SETTINGS_APP, "Notes")
        self.notes_dir_edit.setText(self.settings.value("notesDirectory", defaultValue=default_notes_dir))
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
        self.webui_endpoint_edit.setText(self.settings.value("webui/endpoint", defaultValue=""))
        self.webui_apikey_edit.setText(self.settings.value("webui/apikey", defaultValue=""))
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
        if not endpoint.endswith("/"): endpoint += "/"
        url = endpoint + "api/models"
        headers = {"Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            logging.info(f"Fetching models from {url}")
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
        self.settings.setValue("webui/endpoint", self.webui_endpoint_edit.text().strip())
        self.settings.setValue("webui/apikey", self.webui_apikey_edit.text().strip())
        self.settings.setValue("webui/selected_model", self.webui_model_combo.currentText())
        self.settings_updated_signal.emit()
        self.accept()

# --- Clipboard Item Class --- (No changes from original)
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

# --- P2P Manager (MODIFIED) ---
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
            # Salt is loaded/generated in derive_key and _exchange_salt_and_ready
            self.derive_key() # Initial key derivation
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
                # Salt will be generated and exchanged in the handshake if missing.
                # For now, if no salt, key cannot be derived yet.
                logging.warning("P2P salt not yet set. Key will be derived after salt exchange.")
                self.encryption_key = None
                return
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(), length=AES_KEY_SIZE, salt=salt,
                iterations=PBKDF2_ITERATIONS, backend=default_backend()
            )
            self.encryption_key = kdf.derive(self.password.encode("utf-8"))
            logging.info("P2P encryption key derived successfully.")
        except Exception as e:
            self.encryption_key = None
            logging.error(f"Error deriving P2P encryption key: {e}")

    def encrypt_data(self, data):
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
            logging.warning(f"P2P data decryption failed: {e}") # Don't log payload
            return None

    @Slot()
    def start(self):
        if self.running: return
        self.load_config() # Reloads peers, username, password, port
        if not self.p2p_enabled:
            logging.info("P2P sync is disabled in settings.")
            self.log_message.emit("P2P Disabled")
            return
        if not self.username or not self.password:
            logging.warning("P2P sync cannot start: Username or password missing.")
            self.log_message.emit("P2P Creds Missing")
            self.p2p_enabled = False # Prevent further ops if creds missing
            return
        if not self.peers:
            logging.warning("P2P sync cannot start: No peers configured.")
            self.log_message.emit("P2P No Peers")
            self.p2p_enabled = False
            return
        # Key derivation is attempted in load_config. If salt isn't there yet, it will be None.
        # The handshake will establish salt and then key will be re-derived.
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
        for peer_key, peer in list(self.peers.items()): # Iterate over a copy
            if peer.connection:
                active_connections.append(peer.connection)
                peer.connection = None
            peer.status = "Disconnected"
            peer.authenticated = False
            try: self.peer_status_changed.emit(peer.address, peer.port, peer.status)
            except RuntimeError: pass
        time.sleep(0.2) # Give threads a moment to see self.running is false
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
                handler_thread = threading.Thread(target=self._handle_peer_connection, args=(conn, addr), daemon=True, name=f"P2PHandlerIn-{addr[0]}")
                handler_thread.start()
            except OSError:
                if self.running: logging.warning("P2P Listener: Socket closed or error.")
                break
            except Exception as e:
                if self.running: logging.error(f"P2P Listener: Accept error: {e}")
                time.sleep(1)
        if self.listen_socket:
            try: self.listen_socket.close()
            except: pass
        logging.info("P2P Listener thread stopped.")

    def _connect_to_peers(self):
        while self.running:
            connected_peers_count = 0
            for peer_key, peer in list(self.peers.items()):
                if not self.running: break
                if not peer.connection: # Try to connect if not already connected
                    try:
                        self.peer_status_changed.emit(peer.address, peer.port, "Connecting...")
                        # Create a new socket for each attempt
                        conn_attempt = socket.create_connection((peer.address, peer.port), timeout=10)
                        # If successful, assign to peer and start handler
                        peer.connection = conn_attempt 
                        peer.status = "Connected (Handshaking...)"
                        self.peer_status_changed.emit(peer.address, peer.port, peer.status)
                        logging.info(f"P2P Connector: Connected to {peer.address}:{peer.port}")
                        handler_thread = threading.Thread(target=self._handle_peer_connection, args=(conn_attempt, (peer.address, peer.port)), daemon=True, name=f"P2PHandlerOut-{peer.address}")
                        handler_thread.start()
                        connected_peers_count +=1
                    except socket.timeout:
                        peer.status = "Timeout"
                        self.peer_status_changed.emit(peer.address, peer.port, peer.status)
                        if peer.connection: peer.connection = None # Clear if it was this attempt
                    except ConnectionRefusedError:
                        peer.status = "Refused"
                        self.peer_status_changed.emit(peer.address, peer.port, peer.status)
                        if peer.connection: peer.connection = None
                    except Exception as e:
                        logging.warning(f"P2P Connector: Failed to connect to {peer.address}:{peer.port}: {e}")
                        peer.status = "Error"
                        self.peer_status_changed.emit(peer.address, peer.port, peer.status)
                        if peer.connection: peer.connection = None
                else:
                    connected_peers_count +=1
            if connected_peers_count == 0 and self.peers:
                 self.log_message.emit("P2P No Peers Connected")
            # Sleep for a longer interval before retrying all connections
            for _ in range(300): # Check every 30 seconds (300 * 0.1s)
                 if not self.running: break
                 time.sleep(0.1)
        logging.info("P2P Connector thread stopped.")

    def _exchange_salt_and_ready(self, conn, peer_address_tuple):
        peer_addr_str = f"{peer_address_tuple[0]}:{peer_address_tuple[1]}"
        logging.info(f"[{peer_addr_str}] Starting salt exchange and ready protocol.")
        
        # Ensure this peer has a salt value in settings. Generate if missing.
        my_current_salt_hex = self.settings.value("p2p/salt")
        if not my_current_salt_hex:
            new_salt_bytes = os.urandom(SALT_SIZE)
            my_current_salt_hex = new_salt_bytes.hex()
            self.settings.setValue("p2p/salt", my_current_salt_hex)
            logging.info(f"[{peer_addr_str}] No local salt found, generated new one: {my_current_salt_hex}")
            if self.password: # Key needs to be re-derived if salt is new and password exists
                self.derive_key()

        conn.settimeout(20) # Timeout for handshake steps

        def _send_plain_json(sock, data_dict):
            payload = json.dumps(data_dict).encode("utf-8")
            sock.sendall(len(payload).to_bytes(4, "big") + payload)

        def _recv_plain_json(sock):
            len_bytes = sock.recv(4)
            if not len_bytes or len(len_bytes) < 4:
                logging.warning(f"[{peer_addr_str}] SaltEx: Failed to receive length bytes.")
                return None
            msg_len = int.from_bytes(len_bytes, "big")
            if msg_len <= 0 or msg_len > 1 * 1024 * 1024: # 1MB limit for handshake messages
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

        # Determine initiator/responder based on who connects (client/server)
        # For simplicity, we can try to send first, and if it fails (e.g. peer sends first), adapt.
        # A more robust way: sort IP:Port to decide who initiates certain steps.
        # Here, we use a timeout-based approach: try to receive first, if timeout, then send.
        is_initiator_role = False
        try:
            logging.debug(f"[{peer_addr_str}] SaltEx: Attempting to receive AUTH_SALT_EXCHANGE (acting as responder).")
            conn.settimeout(5) # Short timeout to see if peer sends first
            msg = _recv_plain_json(conn)
            conn.settimeout(20) # Reset to normal handshake timeout

            if msg and msg.get("type") == "AUTH_SALT_EXCHANGE":
                logging.info(f"[{peer_addr_str}] SaltEx: Received AUTH_SALT_EXCHANGE (Responder Path).")
                peer_salt_hex = msg.get("salt")
                if not peer_salt_hex or not isinstance(peer_salt_hex, str) or len(bytes.fromhex(peer_salt_hex)) != SALT_SIZE:
                    logging.warning(f"[{peer_addr_str}] SaltEx: Invalid peer salt received: {peer_salt_hex}")
                    return False

                # Compare salts. The one with lexicographically smaller salt hex string keeps theirs.
                # This ensures both sides converge to the same salt.
                my_salt_for_cmp = self.settings.value("p2p/salt")
                if peer_salt_hex < my_salt_for_cmp:
                    logging.info(f"[{peer_addr_str}] SaltEx: Adopting peer's smaller salt: {peer_salt_hex}. My old: {my_salt_for_cmp}")
                    self.settings.setValue("p2p/salt", peer_salt_hex)
                    if self.password: self.derive_key()
                elif my_salt_for_cmp < peer_salt_hex:
                    logging.info(f"[{peer_addr_str}] SaltEx: My salt {my_salt_for_cmp} is smaller. Peer should adopt.")
                else: # Salts are identical
                    logging.info(f"[{peer_addr_str}] SaltEx: Salts already match: {my_salt_for_cmp}")
                
                # ACK with the agreed-upon salt (which is now self.settings.value("p2p/salt"))
                _send_plain_json(conn, {"type": "AUTH_SALT_EXCHANGE_ACK", "salt": self.settings.value("p2p/salt")})
                logging.info(f"[{peer_addr_str}] SaltEx: Sent AUTH_SALT_EXCHANGE_ACK.")

                # Responder: Expect DONE, send DONE, Expect READY, send READY
                resp_done = _recv_plain_json(conn)
                if not resp_done or resp_done.get("type") != "AUTH_SALT_DONE": return False
                _send_plain_json(conn, {"type": "AUTH_SALT_DONE"})
                resp_ready = _recv_plain_json(conn)
                if not resp_ready or resp_ready.get("type") != "AUTH_READY": return False
                _send_plain_json(conn, {"type": "AUTH_READY"})
                logging.info(f"[{peer_addr_str}] SaltEx: Responder path successful.")
                return True
            else:
                # If msg was None (timeout) or not AUTH_SALT_EXCHANGE, this side initiates.
                is_initiator_role = True
                if msg: logging.debug(f"[{peer_addr_str}] SaltEx: Did not receive salt exchange, or wrong type ({msg.get('type')}). Will initiate.")
        
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
            conn.settimeout(20) # Ensure timeout is reset for subsequent operations

        if is_initiator_role:
            try:
                logging.info(f"[{peer_addr_str}] SaltEx: Initiating salt exchange (Initiator Path).")
                my_salt_to_send = self.settings.value("p2p/salt") # Should be set by now
                _send_plain_json(conn, {"type": "AUTH_SALT_EXCHANGE", "salt": my_salt_to_send })
                logging.info(f"[{peer_addr_str}] SaltEx: Sent AUTH_SALT_EXCHANGE with salt {my_salt_to_send}.")

                resp_ack = _recv_plain_json(conn)
                if not resp_ack or resp_ack.get("type") != "AUTH_SALT_EXCHANGE_ACK": return False
                
                peer_acked_salt_hex = resp_ack.get("salt")
                if not peer_acked_salt_hex or not isinstance(peer_acked_salt_hex, str) or len(bytes.fromhex(peer_acked_salt_hex)) != SALT_SIZE:
                    logging.warning(f"[{peer_addr_str}] SaltEx: Invalid salt in ACK: {peer_acked_salt_hex}")
                    return False

                # The ACKed salt should be the one agreed upon (the smaller one, or same if initially matched)
                # Both sides should now have this salt in their settings if logic is correct.
                if peer_acked_salt_hex != self.settings.value("p2p/salt"):
                    # This implies the peer decided on a different salt than expected, or my salt changed.
                    # Adopt the one from ACK if it's different, assuming peer followed the 

                    # lexicographical comparison rule.
                    self.settings.setValue("p2p/salt", peer_acked_salt_hex)
                    logging.info(f"[{peer_addr_str}] SaltEx: Adopted salt {peer_acked_salt_hex} from peer ACK.")
                    if self.password: self.derive_key() # Re-derive with the new common salt
                elif peer_acked_salt_hex == self.settings.value("p2p/salt"):
                    logging.info(f"[{peer_addr_str}] SaltEx: Salts confirmed match after ACK: {peer_acked_salt_hex}")
                else: # Should not happen if peer also follows the rule
                    logging.warning(f"[{peer_addr_str}] SaltEx: Salt mismatch after ACK. My salt: {self.settings.value('p2p/salt')}, Peer ACKed: {peer_acked_salt_hex}. This is unexpected.")
                    # Potentially force adoption or log error and fail.
                    # For now, let's assume the ACKed salt is the one to use if different.
                    self.settings.setValue("p2p/salt", peer_acked_salt_hex)
                    if self.password: self.derive_key()

                # Initiator: Send DONE, expect DONE, Send READY, expect READY
                _send_plain_json(conn, {"type": "AUTH_SALT_DONE"})
                resp_done = _recv_plain_json(conn)
                if not resp_done or resp_done.get("type") != "AUTH_SALT_DONE": return False
                _send_plain_json(conn, {"type": "AUTH_READY"})
                resp_ready = _recv_plain_json(conn)
                if not resp_ready or resp_ready.get("type") != "AUTH_READY": return False
                logging.info(f"[{peer_addr_str}] SaltEx: Initiator path successful.")
                return True
            except (socket.timeout, ConnectionResetError, BrokenPipeError, json.JSONDecodeError, ValueError, TypeError) as e:
                logging.error(f"[{peer_addr_str}] SaltEx: Error in initiator path: {e}")
                return False
            except Exception as e:
                logging.error(f"[{peer_addr_str}] SaltEx: Generic error in initiator path: {e}", exc_info=True)
                return False
        
        logging.error(f"[{peer_addr_str}] SaltEx: Logic error, unexpected end of function.")
        return False

    def _handle_peer_connection(self, conn, addr): # addr is (ip, port) tuple
        peer_key = f"{addr[0]}:{addr[1]}"
        peer_obj_for_handler = self.peers.get(peer_key) # Use this for known peers
        is_known_peer = bool(peer_obj_for_handler)

        if not is_known_peer:
            # For incoming connections from unknown peers, create a temporary Peer object for this handler
            temp_peer_obj = Peer(addr[0], addr[1], "Handshaking...")
            logging.info(f"P2P Handler: Handling new incoming connection from unknown address {peer_key}")
            # We will use temp_peer_obj for auth, but won't add to self.peers unless fully successful
            # and if dynamic peer addition is desired (currently not implemented).
        else:
            peer_obj_for_handler.connection = conn # Update connection for known peer
            peer_obj_for_handler.status = "Handshaking..."
            try: self.peer_status_changed.emit(peer_obj_for_handler.address, peer_obj_for_handler.port, peer_obj_for_handler.status)
            except RuntimeError: pass

        current_peer_object = peer_obj_for_handler if is_known_peer else temp_peer_obj

        salt_exchange_successful = False
        try:
            salt_exchange_successful = self._exchange_salt_and_ready(conn, addr)
        except Exception as salt_err:
            logging.error(f"[{peer_key}] P2P Handler: Exception during salt exchange: {salt_err}", exc_info=True)
            salt_exchange_successful = False

        if not salt_exchange_successful:
            logging.warning(f"[{peer_key}] P2P Handler: Salt exchange failed. Closing connection.")
            if is_known_peer and self.peers.get(peer_key):
                 self.peers[peer_key].status = "Salt Fail"
                 if self.peers[peer_key].connection == conn: self.peers[peer_key].connection = None
                 try: self.peer_status_changed.emit(current_peer_object.address, current_peer_object.port, "Salt Fail")
                 except RuntimeError: pass
            try: conn.close()
            except: pass
            return
        
        logging.info(f"[{peer_key}] P2P Handler: Salt exchange successful. Proceeding to authentication.")
        current_peer_object.status = "Authenticating..."
        if is_known_peer: # Only emit status for known peers before full auth
            try: self.peer_status_changed.emit(current_peer_object.address, current_peer_object.port, current_peer_object.status)
            except RuntimeError: pass

        authenticated = False
        try:
            # Pass the correct peer object (known or temporary) to _perform_authentication
            authenticated = self._perform_authentication(conn, current_peer_object) 
        except Exception as auth_err:
             logging.error(f"[{peer_key}] P2P Handler: Exception during _perform_authentication: {auth_err}", exc_info=True)
             authenticated = False
        
        if not authenticated:
            logging.warning(f"[{peer_key}] P2P Handler: Authentication failed. Closing connection.")
            current_peer_object.status = "Auth Fail"
            current_peer_object.authenticated = False
            if is_known_peer and self.peers.get(peer_key):
                 if self.peers[peer_key].connection == conn: self.peers[peer_key].connection = None
                 try: self.peer_status_changed.emit(current_peer_object.address, current_peer_object.port, "Auth Fail")
                 except RuntimeError: pass
            try: conn.close()
            except: pass
            return

        logging.info(f"[{peer_key}] P2P Handler: Full authentication successful.")
        current_peer_object.authenticated = True
        current_peer_object.status = "Connected"
        if is_known_peer: # This peer was already in self.peers
            try: self.peer_status_changed.emit(current_peer_object.address, current_peer_object.port, "Connected")
            except RuntimeError: pass
        else:
            # This was an unknown peer that successfully authenticated.
            # Decide if we add them to self.peers (currently, the app only works with pre-configured peers)
            logging.info(f"P2P Handler: Authenticated incoming unknown peer: {peer_key}. Will handle data but not add to permanent peer list.")
            # If dynamic peer addition was desired, it would happen here.
            # self.peers[peer_key] = current_peer_object
            # self.peer_status_changed.emit(current_peer_object.address, current_peer_object.port, "Connected")

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
                        else: break
                    if msg_len != -1:
                        if len(buffer) >= msg_len:
                            encrypted_msg_payload = buffer[:msg_len]
                            buffer = buffer[msg_len:]
                            msg_len = -1
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
                        else: break
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
            if self.peers[peer_key].connection == conn: self.peers[peer_key].connection = None
            try: 
                if self.peer_status_changed is not None:
                    self.peer_status_changed.emit(current_peer_object.address, current_peer_object.port, "Disconnected")
            except RuntimeError: pass
        
        try: conn.shutdown(socket.SHUT_RDWR)
        except (OSError, socket.error): pass
        try: conn.close()
        except (OSError, socket.error): pass
        logging.info(f"P2P Handler for {peer_key} finished.")

    @Slot(dict)
    def emit_received_data_signal(self, data):
        # This slot ensures the signal is emitted from the P2PManager's thread context if called via QMetaObject.invokeMethod
        self.received_data.emit(data)

    def _perform_authentication(self, conn, peer_obj): # peer_obj is the Peer instance (known or temp)
        peer_addr_str = f"{peer_obj.address}:{peer_obj.port}"
        if not self.username or not self.password:
            logging.warning(f"[{peer_addr_str}] Auth: Username or password not set locally.")
            return False
        if not self.encryption_key:
            # This can happen if salt was just established and derive_key() hasn't been called yet in this exact flow for the key.
            # Or if password is bad / salt is missing and derive_key failed earlier.
            logging.warning(f"[{peer_addr_str}] Auth: Encryption key not (yet) derived. Attempting to derive now.")
            self.derive_key() # Attempt to derive it now that salt should be common
            if not self.encryption_key:
                logging.error(f"[{peer_addr_str}] Auth: Encryption key still not derived after attempt. Cannot proceed.")
                return False
        
        try:
            conn.settimeout(25) # Slightly longer timeout for full auth sequence

            # Mutual Authentication (Simplified Challenge-Response)
            # 1. Initiator (self) sends AUTH_INIT with username.
            auth_init_payload = {"type": "AUTH_INIT", "username": self.username}
            encrypted_init = self.encrypt_data(auth_init_payload)
            if not encrypted_init: return False
            self._send_message(conn, encrypted_init)
            logging.info(f"[{peer_addr_str}] Auth: Sent AUTH_INIT.")

            # 2. Responder (peer) sends AUTH_INIT with their username.
            encrypted_resp_init = self._receive_message(conn)
            if not encrypted_resp_init: return False
            decrypted_resp_init = self.decrypt_data(encrypted_resp_init)
            # Peer must also use the same username for this simple auth scheme
            if not decrypted_resp_init or decrypted_resp_init.get("type") != "AUTH_INIT" or decrypted_resp_init.get("username") != self.username:
                logging.warning(f"[{peer_addr_str}] Auth: Invalid peer AUTH_INIT response: {decrypted_resp_init}")
                return False
            logging.info(f"[{peer_addr_str}] Auth: Validated peer's AUTH_INIT.")

            # 3. Initiator sends AUTH_CHALLENGE_1
            challenge1 = os.urandom(32)
            challenge1_payload = {"type": "AUTH_CHALLENGE_1", "challenge": base64.b64encode(challenge1).decode()}
            encrypted_challenge1 = self.encrypt_data(challenge1_payload)
            if not encrypted_challenge1: return False
            self._send_message(conn, encrypted_challenge1)
            logging.info(f"[{peer_addr_str}] Auth: Sent AUTH_CHALLENGE_1.")

            # 4. Responder sends AUTH_RESPONSE_1 (HMAC of challenge1)
            encrypted_resp_challenge1 = self._receive_message(conn)
            if not encrypted_resp_challenge1: return False
            decrypted_resp_challenge1 = self.decrypt_data(encrypted_resp_challenge1)
            if not decrypted_resp_challenge1 or decrypted_resp_challenge1.get("type") != "AUTH_RESPONSE_1":
                logging.warning(f"[{peer_addr_str}] Auth: Invalid AUTH_RESPONSE_1 type: {decrypted_resp_challenge1}")
                return False
            received_hmac1_b64 = decrypted_resp_challenge1.get("response")
            if not received_hmac1_b64: return False
            try: received_hmac1 = base64.b64decode(received_hmac1_b64)
            except Exception: return False
            expected_hmac1 = hmac.new(self.encryption_key, challenge1, hashlib.sha256).digest()
            if not hmac.compare_digest(expected_hmac1, received_hmac1):
                logging.warning(f"[{peer_addr_str}] Auth: HMAC_1 mismatch.")
                return False
            logging.info(f"[{peer_addr_str}] Auth: Validated AUTH_RESPONSE_1 from peer.")

            # 5. Responder sends AUTH_CHALLENGE_2
            encrypted_challenge2 = self._receive_message(conn)
            if not encrypted_challenge2: return False
            decrypted_challenge2 = self.decrypt_data(encrypted_challenge2)
            if not decrypted_challenge2 or decrypted_challenge2.get("type") != "AUTH_CHALLENGE_2":
                logging.warning(f"[{peer_addr_str}] Auth: Invalid AUTH_CHALLENGE_2 type: {decrypted_challenge2}")
                return False
            challenge2_b64 = decrypted_challenge2.get("challenge")
            if not challenge2_b64: return False
            try: challenge2_bytes = base64.b64decode(challenge2_b64)
            except Exception: return False
            logging.info(f"[{peer_addr_str}] Auth: Received AUTH_CHALLENGE_2 from peer.")

            # 6. Initiator sends AUTH_RESPONSE_2 (HMAC of challenge2)
            response2_hmac = hmac.new(self.encryption_key, challenge2_bytes, hashlib.sha256).digest()
            response2_payload = {"type": "AUTH_RESPONSE_2", "response": base64.b64encode(response2_hmac).decode()}
            encrypted_response2 = self.encrypt_data(response2_payload)
            if not encrypted_response2: return False
            self._send_message(conn, encrypted_response2)
            logging.info(f"[{peer_addr_str}] Auth: Sent AUTH_RESPONSE_2.")

            # 7. Initiator sends AUTH_OK.
            auth_ok_payload = {"type": "AUTH_OK"}
            encrypted_auth_ok = self.encrypt_data(auth_ok_payload)
            if not encrypted_auth_ok: return False
            self._send_message(conn, encrypted_auth_ok)
            logging.info(f"[{peer_addr_str}] Auth: Sent AUTH_OK.")

            # 8. Responder sends AUTH_OK.
            encrypted_peer_auth_ok = self._receive_message(conn)
            if not encrypted_peer_auth_ok: return False
            decrypted_peer_auth_ok = self.decrypt_data(encrypted_peer_auth_ok)
            if not decrypted_peer_auth_ok or decrypted_peer_auth_ok.get("type") != "AUTH_OK":
                logging.warning(f"[{peer_addr_str}] Auth: Invalid peer AUTH_OK: {decrypted_peer_auth_ok}")
                return False
            
            logging.info(f"Authentication successful with {peer_addr_str}")
            conn.settimeout(None) # Disable timeout for normal operation after successful auth
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
            raise # Re-raise to be caught by caller, which handles peer state
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
            if msg_len <= 0 or msg_len > 10 * 1024 * 1024: # 10MB limit
                logging.error(f"P2P Receive: Invalid message length: {msg_len}")
                # Consider closing connection here or returning specific error
                return None 
            chunks = []
            bytes_recd = 0
            while bytes_recd < msg_len:
                # Check self.running frequently if this loop can be long
                if not self.running: 
                    logging.info("P2P Receive: Manager stopping, aborting receive.")
                    return None
                chunk = conn.recv(min(msg_len - bytes_recd, 8192))
                if not chunk: # Connection closed by peer
                    logging.warning("P2P Receive: Connection closed by peer while receiving message body.")
                    return None
                chunks.append(chunk)
                bytes_recd += len(chunk)
            return b"".join(chunks)
        except socket.timeout:
            logging.debug("P2P Receive: Socket timeout.") # Debug level, as timeouts are expected during handshake phases
            return None
        except socket.error as e:
            logging.error(f"P2P Receive: Socket error: {e}")
            return None # Indicates connection issue
        except Exception as e:
            logging.error(f"P2P Receive: Unexpected error: {e}")
            return None

    @Slot(dict)
    def send_to_all_peers(self, data_dict_to_send):
        if not self.running or not self.p2p_enabled:
            logging.debug("P2P SendAll: Not running or P2P disabled.")
            return
        if not self.encryption_key:
            logging.error("P2P SendAll: Encryption key not available. Cannot send.")
            return
        
        encrypted_payload = self.encrypt_data(data_dict_to_send)
        if not encrypted_payload:
            logging.error("P2P SendAll: Failed to encrypt data. Aborting send.")
            return

        sent_count = 0
        # Iterate over a copy of items in case a peer disconnects and modifies the dict during iteration
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
                        try: peer.connection.close()
                        except: pass
                        peer.connection = None # Clear the connection object
                    try: 
                        if self.peer_status_changed is not None:
                            self.peer_status_changed.emit(peer.address, peer.port, peer.status)
                    except RuntimeError: pass # Main window might be closing
        if sent_count > 0:
            logging.info(f"P2P SendAll: Sent data (type: {data_dict_to_send.get('type')}) to {sent_count} authenticated peers.")
        elif self.peers: # Only log if there were peers to send to
            logging.info(f"P2P SendAll: Data (type: {data_dict_to_send.get('type')}) not sent (no authenticated peers currently available).")

# --- WebUI Worker --- (No changes from original, assuming it's correct)
class WebUIWorker(QObject):
    finished = Signal()
    error = Signal(str)
    models_fetched = Signal(list)
    stream_chunk = Signal(str)
    stream_finished = Signal()

    def __init__(self, endpoint, api_key, model=None, messages=None):
        super().__init__()
        self.endpoint = endpoint
        self.api_key = api_key
        self.model = model
        self.messages = messages if messages else []
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
            logging.info(f"Worker sending chat request to {url} for model {self.model} with {len(self.messages)} messages.")
            with requests.post(url, headers=headers, json=payload, stream=True, timeout=300) as response:
                response.raise_for_status()
                for line in response.iter_lines(decode_unicode=True):
                    if not self._running: break
                    if line.startswith("data:"):
                        json_str = line[len("data:"):].strip()
                        if json_str == "[DONE]": break
                        if json_str:
                            try:
                                data = json.loads(json_str)
                                if "choices" in data and data["choices"]:
                                    delta = data["choices"][0].get("delta", {})
                                    message_content = delta.get("content", "")
                                    if message_content: self.stream_chunk.emit(message_content)
                            except json.JSONDecodeError:
                                logging.warning(f"JSON decode error in stream line: {line}")
                            except Exception as e:
                                logging.error(f"Error processing stream part: {e} - Line: {line}")
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

# --- Assistant Widget --- (No changes from original, assuming it's correct)
class AssistantWidget(QWidget):
    send_conversation_signal = Signal(list)
    def __init__(self, parent=None):
        super().__init__(parent)
        self.conversation_history = []
        self.current_assistant_response = ""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5,5,5,5)
        title_layout = QHBoxLayout()
        title_layout.addWidget(QLabel("Assistant"))
        title_layout.addStretch()
        self.new_chat_button = QPushButton("New Chat")
        self.new_chat_button.setToolTip("Start a new conversation")
        title_layout.addWidget(self.new_chat_button)
        layout.addLayout(title_layout)
        self.conversation_view = QPlainTextEdit()
        self.conversation_view.setReadOnly(True)
        layout.addWidget(self.conversation_view)
        prompt_layout = QHBoxLayout()
        self.prompt_input = QLineEdit()
        self.prompt_input.setPlaceholderText("Enter your prompt...")
        self.send_button = QPushButton("Send")
        prompt_layout.addWidget(self.prompt_input)
        prompt_layout.addWidget(self.send_button)
        layout.addLayout(prompt_layout)
        self.send_button.clicked.connect(self.send_prompt)
        self.prompt_input.returnPressed.connect(self.send_prompt)
        self.new_chat_button.clicked.connect(self.clear_conversation)
    def send_prompt(self):
        prompt_text = self.prompt_input.text().strip()
        if prompt_text:
            self.append_text_to_view(f"\n**You:** {prompt_text}\n**Assistant:** ")
            self.conversation_history.append({"role": "user", "content": prompt_text})
            self.prompt_input.clear()
            self.send_button.setEnabled(False)
            self.new_chat_button.setEnabled(False)
            self.current_assistant_response = ""
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
        self.append_text_to_view("\n")
        logging.info(f"Assistant stream finished. History size: {len(self.conversation_history)}")

# --- Main Window (MODIFIED for Sidebar and Tray Icon) ---
class MainWindow(QMainWindow):
    send_p2p_data_signal = Signal(dict)
    start_webui_chat_signal = Signal(str, str, str, list)

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
        self.load_splitter_state()
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
        self.p2p_thread = QThread(self)
        self.p2p_manager = P2PManager(self.settings)
        self.p2p_manager.moveToThread(self.p2p_thread)
        self.p2p_thread.started.connect(self.p2p_manager.start)
        self.p2p_manager.log_message.connect(self.log_status)
        self.p2p_manager.peer_status_changed.connect(self.update_peer_status_ui)
        self.p2p_manager.received_data.connect(self.handle_received_p2p_data)
        self.send_p2p_data_signal.connect(self.p2p_manager.send_to_all_peers)
        self.p2p_thread.start()
        self.webui_thread = QThread(self)
        self.webui_worker = None
        self.assistant_widget.send_conversation_signal.connect(self.handle_assistant_conversation)
        self.start_webui_chat_signal.connect(self.start_webui_chat_worker)
        self.create_tray_icon() # Create tray icon before auto-hide setup
        self.auto_hide_timer = QTimer(self)
        self.auto_hide_timer.setInterval(250) # Check mouse position interval
        self.auto_hide_timer.timeout.connect(self.check_mouse_position_for_auto_hide)
        self.is_mouse_over_window = False # Track if mouse is currently over the window
        self.auto_hide_enabled = self.settings.value("window/autoHide", defaultValue=True, type=bool)
        if hasattr(self, 'auto_hide_action'): # Ensure tray action exists
            self.auto_hide_action.setChecked(self.auto_hide_enabled)
        if self.auto_hide_enabled:
            self.auto_hide_timer.start()
        self.position_as_sidebar()
        self.installEventFilter(self) # For focus events
        self.update_assistant_availability()
        logging.info("MainWindow initialized.")
        # Initial visibility based on auto-hide logic (might start hidden)
        if self.auto_hide_enabled:
            self.hide() # Start hidden if auto-hide is on
            QTimer.singleShot(100, self.check_mouse_position_for_auto_hide) # Check immediately
        else:
            self.show_window() # Show normally if auto-hide is off

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
            # Fallback to default, try creating again
            self.notes_directory = default_notes_dir 
            try: os.makedirs(self.notes_directory, exist_ok=True) 
            except: pass # If still fails, it's problematic but continue
        self.webui_endpoint = self.settings.value("webui/endpoint", defaultValue="")
        self.webui_apikey = self.settings.value("webui/apikey", defaultValue="")
        self.webui_model = self.settings.value("webui/selected_model", defaultValue="")
        self.auto_hide_enabled = self.settings.value("window/autoHide", defaultValue=True, type=bool)
        current_always_on_top = bool(self.windowFlags() & Qt.WindowStaysOnTopHint)
        saved_always_on_top = self.settings.value("window/alwaysOnTop", defaultValue=True, type=bool)
        if current_always_on_top != saved_always_on_top:
            self.toggle_always_on_top(saved_always_on_top, save_setting=False) # Apply saved, don't re-save

    @Slot()
    def settings_updated(self):
        logging.info("Settings updated, reloading configuration...")
        old_notes_dir = self.notes_directory
        # P2P manager needs to be stopped before its settings are reloaded by its own load_config
        if self.p2p_manager and self.p2p_thread.isRunning():
            logging.info("Stopping P2P Manager for settings update...")
            self.p2p_manager.stop() # This will set self.p2p_manager.running to False
            # Wait for P2P manager to actually stop its threads if possible, or use a timer for restart
            # For simplicity, a timer is often used.
        self.load_settings() # Reloads general, WebUI, autoHide, alwaysOnTop settings
        if old_notes_dir != self.notes_directory:
            self.save_all_notes() # Save notes from old dir if any
            self.load_notes()     # Load notes from new dir
        # Restart P2P manager if it was enabled
        if self.settings.value("p2p/enabled", defaultValue=False, type=bool):
            logging.info("Restarting P2P Manager due to settings change...")
            # Ensure P2PManager's internal config is reloaded before starting
            QTimer.singleShot(500, lambda: self.p2p_manager.start() if self.p2p_manager else None)
        else: # If P2P was disabled in settings, ensure it's stopped
            if self.p2p_manager and self.p2p_manager.running:
                 self.p2p_manager.stop()
        self.update_assistant_availability()
        # Apply auto-hide setting from tray menu if it exists
        if hasattr(self, 'auto_hide_action'):
            self.auto_hide_action.setChecked(self.auto_hide_enabled)
            self.toggle_auto_hide(self.auto_hide_enabled, save_setting=False) # Apply, don't re-save
        if hasattr(self, 'always_on_top_action'):
            self.always_on_top_action.setChecked(self.settings.value("window/alwaysOnTop", defaultValue=True, type=bool))
            # toggle_always_on_top already called in load_settings if different

    def create_clipboard_widget(self): # (No changes from original)
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5,5,5,5)
        layout.addWidget(QLabel("Clipboard History (Max 30)"))
        self.clipboard_list = QListWidget()
        self.clipboard_list.setIconSize(QSize(64, 64))
        self.clipboard_list.itemDoubleClicked.connect(self.on_clipboard_item_activated)
        layout.addWidget(self.clipboard_list)
        return widget

    def create_process_widget(self): # (No changes from original)
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5,5,5,5)
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

    def create_notepad_widget(self): # (No changes from original)
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5,5,5,5)
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

    def update_assistant_availability(self): # (No changes from original)
        enabled = bool(self.webui_endpoint and self.webui_model)
        self.assistant_widget.setEnabled(enabled)
        if not enabled:
            self.assistant_widget.prompt_input.setPlaceholderText("Configure WebUI Endpoint and Model in Settings...")
            self.assistant_widget.clear_conversation()
        else:
            self.assistant_widget.prompt_input.setPlaceholderText("Enter your prompt...")
        logging.info(f"Assistant enabled status: {enabled}")

    @Slot(list)
    def handle_assistant_conversation(self, messages): # (No changes from original)
        if not self.webui_endpoint or not self.webui_model:
            QMessageBox.warning(self, "Assistant Error", "WebUI Endpoint or Model not configured in Settings.")
            self.assistant_widget.on_stream_finished()
            return
        if self.webui_worker and self.webui_thread.isRunning():
            logging.warning("Assistant is already processing a request.")
            return
        self.start_webui_chat_signal.emit(self.webui_endpoint, self.webui_apikey, self.webui_model, messages)

    @Slot(str, str, str, list)
    def start_webui_chat_worker(self, endpoint, api_key, model, messages): # (No changes from original)
        if self.webui_worker and self.webui_thread.isRunning():
            logging.warning("Stopping lingering WebUI worker before starting new one.")
            self.webui_worker.stop()
            self.webui_thread.quit()
            self.webui_thread.wait(500)
        self.webui_worker = WebUIWorker(endpoint, api_key, model, messages)
        self.webui_worker.moveToThread(self.webui_thread)
        try: self.webui_worker.stream_chunk.disconnect() 
        except RuntimeError: pass
        try: self.webui_worker.stream_finished.disconnect() 
        except RuntimeError: pass
        try: self.webui_worker.error.disconnect() 
        except RuntimeError: pass
        try: self.webui_worker.finished.disconnect() 
        except RuntimeError: pass
        self.webui_worker.stream_chunk.connect(self.assistant_widget.handle_stream_chunk)
        self.webui_worker.stream_finished.connect(self.assistant_widget.on_stream_finished)
        self.webui_worker.error.connect(self.handle_webui_error)
        self.webui_worker.finished.connect(self.webui_thread.quit)
        self.webui_worker.finished.connect(self.webui_worker.deleteLater)
        self.webui_thread.started.connect(self.webui_worker.run_chat_stream)
        self.webui_thread.finished.connect(lambda: setattr(self, 'webui_worker', None))
        self.webui_thread.start()
        logging.info("WebUI chat worker started.")

    @Slot(str)
    def handle_webui_error(self, error_message): # (No changes from original)
        logging.error(f"WebUI Worker Error: {error_message}")
        QMessageBox.critical(self, "Assistant Error", f"An error occurred:\n{error_message}")
        if self.assistant_widget:
            self.assistant_widget.on_stream_finished()

    def position_as_sidebar(self): # (No changes from original)
        try:
            screen = QGuiApplication.primaryScreen()
            if not screen: return
            available_geo = screen.availableGeometry()
            window_height = available_geo.height()
            # Position at the right edge
            self.setGeometry(available_geo.width() - SIDEBAR_WIDTH, available_geo.top(), SIDEBAR_WIDTH, window_height)
        except Exception as e:
            logging.error(f"Error positioning window: {e}")
            self.resize(SIDEBAR_WIDTH, 800) # Fallback size

    def load_splitter_state(self): # (No changes from original)
        try:
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

    def set_default_splitter_sizes(self): # (No changes from original)
        total_height = self.central_widget.height()
        if total_height <= 0: total_height = 800 # Fallback if height not determined yet
        sizes = [int(total_height * 0.15), int(total_height * 0.15), int(total_height * 0.30), int(total_height * 0.40)]
        self.central_widget.setSizes(sizes)
        logging.info(f"Set default splitter sizes: {sizes}")

    def adjust_splitter_sizes(self): # (No changes from original)
        sizes = self.central_widget.sizes()
        if len(sizes) != 4: 
            logging.warning("Splitter size count mismatch, resetting to defaults.")
            self.set_default_splitter_sizes()
            return
        total_height = self.central_widget.height()
        current_sum = sum(sizes)
        if total_height <= 0 or current_sum <= 0: return
        if abs(current_sum - total_height) > 10:
            scale_factor = total_height / current_sum
            new_sizes = [max(10, int(s * scale_factor)) for s in sizes]
            new_sizes[-1] = max(10, total_height - sum(new_sizes[:-1]))
            if sum(new_sizes) == total_height and all(s >= 10 for s in new_sizes):
                self.central_widget.setSizes(new_sizes)
                logging.debug(f"Adjusted splitter sizes proportionally: {new_sizes}")
            else:
                self.set_default_splitter_sizes()

    def save_splitter_state(self): # (No changes from original)
        try:
            state = self.central_widget.saveState()
            self.settings.setValue("window/splitterState", state)
            logging.info("Saved splitter state.")
        except Exception as e:
            logging.error(f"Error saving splitter state: {e}")

    def apply_stylesheet(self): # (No changes from original)
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
        self.auto_hide_action.setChecked(self.auto_hide_enabled) # Use value loaded in __init__ or load_settings
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
        if reason == QSystemTrayIcon.Trigger: # Typically left click
            self.toggle_window_visibility()
        # elif reason == QSystemTrayIcon.Context: # Right click handled by context menu
            # pass 

    def show_window(self):
        # Determine the correct flags for a frameless tool window
        new_flags = Qt.FramelessWindowHint | Qt.Tool
        
        # Add WindowStaysOnTopHint if the corresponding action is checked
        if hasattr(self, 'always_on_top_action') and self.always_on_top_action.isChecked():
            new_flags |= Qt.WindowStaysOnTopHint
        
        # Set the window flags. This operation can hide the window, so it's done before showing.
        self.setWindowFlags(new_flags)
        
        # Now, make the window visible and bring it to the front.
        self.showNormal()     # Ensures the window is shown and de-minimized.
        self.activateWindow() # Attempts to make the window the active, focused window.
        self.raise_()         # Raises the window to the top of the window stack (respecting StaysOnTopHint).
        logging.debug(f"show_window called, flags set to: {hex(int(new_flags))}")

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

    def open_settings_dialog(self): # (No changes from original)
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

    # --- Event Handling (MODIFIED for Sidebar and Focus) ---
    def enterEvent(self, event: QEvent): # Mouse enters window area
        if self.auto_hide_enabled:
            self.is_mouse_over_window = True
            logging.debug("Mouse entered window area.")
        super().enterEvent(event)

    def leaveEvent(self, event: QEvent): # Mouse leaves window area
        if self.auto_hide_enabled:
            self.is_mouse_over_window = False
            logging.debug("Mouse left window area. Checking for auto-hide.")
            # Check immediately if we should hide (e.g., if window is not active)
            QTimer.singleShot(50, self.check_mouse_position_for_auto_hide)
        super().leaveEvent(event)

    def eventFilter(self, obj, event: QEvent):
        # Handle focus out for auto-hide and P2P sync trigger
        if event.type() == QEvent.WindowDeactivate:
            logging.debug("Window deactivated (lost focus).")
            if self.auto_hide_enabled and not self.is_mouse_over_window:
                # If mouse is not over the window when it loses focus, hide it.
                # This helps with the "click outside to hide" behavior.
                logging.debug("Window deactivated and mouse not over, hiding.")
                self.hide_window()
            if self.needs_sync:
                self.trigger_sync()
                self.needs_sync = False
        elif event.type() == QApplication.focusChanged:
            if not QGuiApplication.focusWindow(): # No window in this app has focus
                logging.debug("Application lost focus.")
                if self.auto_hide_enabled and self.isVisible() and not self.is_mouse_over_window:
                    # More aggressive hide if app loses focus and mouse isn't over sidebar
                    logging.debug("Application lost focus, sidebar visible, mouse not over -> hiding.")
                    self.hide_window()
        return super().eventFilter(obj, event)

    def closeEvent(self, event: QCloseEvent):
        if self.allow_close:
            logging.info("Closing application...")
            self.save_splitter_state()
            self.save_all_notes()
            if self.p2p_manager: self.p2p_manager.stop()
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
            self.settings.sync() # Ensure settings are written to disk
            logging.info("Application closed gracefully.")
            event.accept()
            QApplication.instance().quit() # Ensure application quits fully
        else:
            logging.debug("Close event intercepted, hiding window to tray.")
            event.ignore()
            self.hide_window()

    # --- Clipboard Methods --- (No changes from original)
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
                    if last_item.data_type == "image" and self.pixmaps_equal(last_item.data, current_pixmap): is_new = False
                if is_new: new_item_data = current_pixmap; data_type = "image"
            elif mime_data.hasText() and current_text:
                is_new = True
                if self.clipboard_history:
                    last_item = self.clipboard_history[0]
                    if last_item.data_type == "text" and last_item.data == current_text: is_new = False
                if is_new: new_item_data = current_text; data_type = "text"
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
        if not (0 <= index < len(self.clipboard_history)): return
        history_item = self.clipboard_history[index]
        try:
            self.monitoring_clipboard = False
            self.clipboard.clear()
            mime_data = QMimeData()
            if history_item.data_type == "text": mime_data.setText(history_item.data)
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

    # --- Process Manager Methods --- (No changes from original)
    def update_process_list(self):
        try:
            new_processes = {}
            for proc in psutil.process_iter(["pid", "name"]):
                try: new_processes[proc.info["pid"]] = proc.info["name"]
                except (psutil.NoSuchProcess, psutil.AccessDenied): continue
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
                        try: p.wait(timeout=0.2); killed += 1
                        except psutil.TimeoutExpired:
                            p.kill(); p.wait(timeout=0.2); killed += 1
                    except psutil.NoSuchProcess: killed += 1
                    except psutil.AccessDenied: failed += 1
                    except Exception: failed += 1
                self.log_status(f"Process termination: Killed/Exited: {killed}, Failed: {failed}.", 5000)
                self.update_process_list()
        except Exception as e:
            logging.error(f"Error during kill process: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Error during process termination: {e}")

    @Slot()
    def find_process_by_port(self): # (No changes from original)
        port_text = self.port_search_input.text().strip()
        if not port_text.isdigit():
            QMessageBox.warning(self, "Invalid Port", "Please enter a valid port number.")
            return
        try:
            port = int(port_text)
            if not (1 <= port <= 65535): raise ValueError("Port out of range")
        except ValueError:
            QMessageBox.warning(self, "Invalid Port", "Port number must be between 1 and 65535.")
            return
        found_pids = set(); process_info = []
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
                    proc = psutil.Process(pid); name = proc.name()
                    process_info.append(f"- PID: {pid}, Name: {name}")
                    for i in range(self.process_list.count()):
                        item = self.process_list.item(i)
                        if item and item.data(Qt.UserRole) == pid:
                            items_to_select.append(item); break
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

    # --- Notepad Methods --- (No changes from original, assuming correct)
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
                if not tab_text.endswith(" *"): self.notepad_tabs.setTabText(index, tab_text + " *")
            else:
                if tab_text.endswith(" *"): self.notepad_tabs.setTabText(index, tab_text[:-2])
            style = tab_bar.style(); style.unpolish(tab_bar); style.polish(tab_bar) # Refresh style
        except Exception as e: logging.error(f"Error marking tab unsaved: {e}")
    def save_current_note_if_changed(self):
        for index, changed in list(self.notes_changed.items()):
            if changed and index != self.notepad_tabs.currentIndex():
                self.save_note(index, mark_saved=True)
    def save_all_notes(self):
        logging.info("Saving all unsaved notes...")
        saved_count = 0
        for index in range(self.notepad_tabs.count()):
            if self.notes_changed.get(index, False):
                if self.save_note(index, mark_saved=True): saved_count += 1
        logging.info(f"Saved {saved_count} notes.")
    def save_note(self, index, mark_saved=True):
        if not (0 <= index < self.notepad_tabs.count()): return False
        widget = self.notepad_tabs.widget(index)
        tab_name = self.notepad_tabs.tabText(index)
        if tab_name.endswith(" *"): tab_name = tab_name[:-2]
        if isinstance(widget, QTextEdit):
            filepath = self.get_note_filepath(tab_name)
            content = widget.toPlainText(); timestamp = time.time()
            try:
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                with open(filepath, "w", encoding="utf-8") as f: f.write(content)
                widget.setProperty("timestamp", timestamp)
                if mark_saved:
                    self.notes_changed[index] = False
                    self.mark_tab_unsaved(index, False)
                logging.info(f"Saved note \'{tab_name}\' to {filepath}")
                self.schedule_sync("notepad_update", {"name": tab_name, "content": content, "timestamp": timestamp})
                return True
            except Exception as e:
                QMessageBox.warning(self, "Save Error", f"Failed to save note \'{tab_name}\':\n{e}")
                return False
        return False
    def get_note_filepath(self, note_name):
        safe_filename = re.sub(r"[\/*?:\"<>|]", "_", note_name) + ".txt"
        return os.path.join(self.notes_directory, safe_filename)
    def load_notes(self):
        logging.info(f"Loading notes from: {self.notes_directory}")
        try:
            while self.notepad_tabs.count() > 0: self.notepad_tabs.removeTab(0)
            self.notes_changed.clear()
            if not os.path.isdir(self.notes_directory):
                return self.add_initial_notepad_tab()
            loaded_count = 0
            for filename in sorted(os.listdir(self.notes_directory)):
                if filename.endswith(".txt"):
                    filepath = os.path.join(self.notes_directory, filename)
                    tab_name = os.path.splitext(filename)[0]
                    try:
                        with open(filepath, "r", encoding="utf-8") as f: content = f.read()
                        timestamp = os.path.getmtime(filepath)
                        self.add_new_notepad_tab(name=tab_name, content=content, timestamp=timestamp)
                        loaded_count += 1
                    except Exception as e: logging.error(f"Error loading note \'{filename}\': {e}")
            if loaded_count == 0: self.add_initial_notepad_tab()
            logging.info(f"Loaded {loaded_count} notes.")
        except Exception as e:
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
                    if i > 1000: name = f"Untitled_{int(time.time())}"; break
            text_edit = QTextEdit()
            text_edit.setPlainText(content)
            text_edit.setProperty("timestamp", timestamp or time.time())
            index = self.notepad_tabs.addTab(text_edit, name)
            self.notepad_tabs.setCurrentIndex(index)
            self.notes_changed[index] = False
            text_edit.textChanged.connect(self.on_notepad_text_changed)
            self.mark_tab_unsaved(index, False)
        except Exception as e: QMessageBox.warning(self, "Error", f"Failed to add new note tab: {e}")
    def rename_current_notepad_tab(self):
        idx = self.notepad_tabs.currentIndex(); old_name_display = self.notepad_tabs.tabText(idx)
        if idx == -1: return
        was_unsaved = old_name_display.endswith(" *"); old_name_actual = old_name_display[:-2] if was_unsaved else old_name_display
        old_filepath = self.get_note_filepath(old_name_actual)
        new_name_actual, ok = QInputDialog.getText(self, "Rename Note", "New name:", QLineEdit.Normal, old_name_actual)
        if ok and new_name_actual and new_name_actual != old_name_actual:
            new_filepath = self.get_note_filepath(new_name_actual)
            if os.path.exists(new_filepath):
                QMessageBox.warning(self, "Rename Failed", f"Note \'{new_name_actual}\' already exists."); return
            try:
                current_widget = self.notepad_tabs.widget(idx)
                if isinstance(current_widget, QTextEdit):
                    content_to_save = current_widget.toPlainText()
                    os.makedirs(os.path.dirname(new_filepath), exist_ok=True)
                    with open(new_filepath, "w", encoding="utf-8") as f: f.write(content_to_save)
                    if os.path.exists(old_filepath) and old_filepath != new_filepath: os.remove(old_filepath)
                    new_name_display = new_name_actual + (" *" if was_unsaved else "")
                    self.notepad_tabs.setTabText(idx, new_name_display)
                    self.notes_changed[idx] = False; self.mark_tab_unsaved(idx, False)
                    self.schedule_sync("notepad_rename", {"old_name": old_name_actual, "new_name": new_name_actual})
            except Exception as e:
                QMessageBox.warning(self, "Rename Error", f"Failed to rename note: {e}")
                self.notepad_tabs.setTabText(idx, old_name_display) # Revert
    def close_notepad_tab(self, index):
        if not (0 <= index < self.notepad_tabs.count()): return
        tab_name_display = self.notepad_tabs.tabText(index); tab_name_actual = tab_name_display[:-2] if tab_name_display.endswith(" *") else tab_name_display
        is_unsaved = self.notes_changed.get(index, False)
        if is_unsaved:
            reply = QMessageBox.question(self, "Unsaved Changes", f"Save \'{tab_name_actual}\'?", QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel)
            if reply == QMessageBox.Cancel: return
            elif reply == QMessageBox.Save and not self.save_note(index, mark_saved=True): return
        try:
            self.notepad_tabs.removeTab(index)
            if index in self.notes_changed: del self.notes_changed[index]
            # Re-index notes_changed
            new_notes_changed = {}
            for old_idx, status in self.notes_changed.items():
                if old_idx > index: new_notes_changed[old_idx - 1] = status
                elif old_idx < index: new_notes_changed[old_idx] = status
            self.notes_changed = new_notes_changed
            self.schedule_sync("notepad_delete", {"name": tab_name_actual})
            if self.notepad_tabs.count() == 0: self.add_initial_notepad_tab()
        except Exception as e: logging.error(f"Error closing notepad tab {index}: {e}")
    def show_notepad_tab_context_menu(self, position):
        try:
            tab_bar = self.notepad_tabs.tabBar(); index = tab_bar.tabAt(position)
            if index != -1:
                menu = QMenu(); rename_action = menu.addAction("Rename"); close_action = menu.addAction("Close")
                action = menu.exec(tab_bar.mapToGlobal(position))
                if action == rename_action: self.rename_current_notepad_tab()
                elif action == close_action: self.close_notepad_tab(index)
        except Exception as e: logging.error(f"Error in notepad context menu: {e}")

    # --- P2P Sync Logic (MODIFIED for robustness) ---
    def schedule_sync(self, data_type, details=None):
        self.needs_sync = True
        logging.debug(f"Sync scheduled for {data_type}. Details: {details}")
        # Optionally, could add a small delay here if syncs are too frequent
        # QTimer.singleShot(200, self.trigger_sync_if_needed) 
        # For now, direct trigger on focus out is fine.

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
                    timestamp = widget.property("timestamp") or time.time() # Ensure timestamp exists
                    notepad_data[tab_name_actual] = {"content": widget.toPlainText(), "timestamp": timestamp}
            sync_payload = {
                "type": "SYNC_DATA", "clipboard": clipboard_data,
                "notepad": notepad_data, "sender_timestamp": time.time()
            }
            self.send_p2p_data_signal.emit(sync_payload)
            self.log_status("Sync data prepared for P2P manager.", 3000)
            self.needs_sync = False # Reset flag after attempting to send
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
                # Check sender timestamp to prevent processing very old messages if clocks are way off (optional)
                # sender_ts = data.get("sender_timestamp", 0)
                # if time.time() - sender_ts > 300: # Ignore if older than 5 mins
                #     logging.warning(f"Ignoring old SYNC_DATA from sender (timestamp: {sender_ts})")
                #     return
                remote_clipboard = data.get("clipboard", [])
                self.sync_clipboard_history(remote_clipboard)
                remote_notepad = data.get("notepad", {})
                self.sync_notepad_content(remote_notepad)
                self.log_status("P2P Sync data received and processed.", 3000)
            elif data_type == "NOTEPAD_RENAME":
                old_name = data.get("old_name"); new_name = data.get("new_name")
                if old_name and new_name: self.handle_remote_notepad_rename(old_name, new_name)
            elif data_type == "NOTEPAD_DELETE":
                 name_to_delete = data.get("name")
                 if name_to_delete: self.handle_remote_notepad_delete(name_to_delete)
        except Exception as e:
            logging.error(f"Error handling received P2P data: {e}", exc_info=True)
            self.log_status(f"P2P Sync Process Error: {e}", 5000)

    def sync_clipboard_history(self, remote_history_dicts):
        logging.debug(f"Syncing clipboard. Remote items: {len(remote_history_dicts)}, Local items: {len(self.clipboard_history)}")
        # Create a set of local item representations (e.g., timestamp + content hash) for quick checks
        # For simplicity, using timestamp as a primary key, assuming they are unique enough for clipboard items.
        local_item_timestamps = {item.timestamp: item for item in self.clipboard_history}
        new_items_added = False
        for item_dict in remote_history_dicts:
            remote_item = ClipboardItem.from_dict(item_dict)
            if remote_item:
                if remote_item.timestamp not in local_item_timestamps:
                    # Basic check: if same content already exists with a very close timestamp, maybe skip?
                    # This is complex. For now, add if timestamp is new.
                    self.clipboard_history.append(remote_item)
                    new_items_added = True
                    logging.debug(f"Added remote clipboard item (ts: {remote_item.timestamp})")
                # else: item already exists (by timestamp)
            else: logging.warning("Failed to create ClipboardItem from remote dict during sync.")
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

                # Conflict resolution: If remote is newer and local is not unsaved, update local.
                # If local is unsaved and newer than remote, local wins (do nothing here, it will be sent out later).
                # If timestamps are same, assume content is same (or take remote if unsure, but could cause edit ping-pong).
                # If local is unsaved but remote is much newer, user might get a prompt or remote wins.
                # Simple: remote wins if newer, unless local is unsaved AND local is newer.
                if remote_timestamp > local_timestamp:
                    if local_is_unsaved and local_timestamp > remote_timestamp:
                        logging.info(f"Note \'{remote_name}\': Local unsaved version is newer, keeping local.")
                    elif local_widget.toPlainText() != remote_content:
                        logging.info(f"Note \'{remote_name}\': Updating with newer remote content (RemoteTS: {remote_timestamp}, LocalTS: {local_timestamp}).")
                        # Preserve cursor position if possible (more complex, skipping for now)
                        local_widget.setPlainText(remote_content)
                        local_widget.setProperty("timestamp", remote_timestamp)
                        self.notes_changed[local_index] = False # Mark as synced
                        self.mark_tab_unsaved(local_index, False)
                        ui_changed = True
                elif local_timestamp > remote_timestamp and not local_is_unsaved:
                    # Local is newer and saved, this implies remote is outdated. Local will send its version.
                    logging.debug(f"Note \'{remote_name}\': Local saved version is newer. Remote will update.")
                # If local_is_unsaved and local_timestamp <= remote_timestamp, this is a conflict.
                # Current logic: if remote is newer, it overwrites. If local is unsaved but not newer, it gets overwritten.
                # Consider a merge or conflict notification for more advanced scenarios.

            else: # Note exists remotely but not locally: Add it.
                logging.info(f"Note \'{remote_name}\': Adding new note from remote sync.")
                self.add_new_notepad_tab(name=remote_name, content=remote_content, timestamp=remote_timestamp)
                ui_changed = True
        
        # Process deletions: If a local note is not in remote_notepad_data, it means it was deleted on the other side.
        # This is a simple "remote authority" for deletions. More complex logic could check timestamps.
        local_note_names = set(local_tabs_info.keys())
        remote_note_names = set(remote_notepad_data.keys())
        notes_to_delete_locally = local_note_names - remote_note_names

        if notes_to_delete_locally:
            for note_name_to_delete in notes_to_delete_locally:
                logging.info(f"Note \'{note_name_to_delete}\': Removing as it was deleted remotely.")
                local_info = local_tabs_info[note_name_to_delete]
                # Close tab without save prompt as it's a remote deletion
                self.notepad_tabs.removeTab(local_info["index"])
                if local_info["index"] in self.notes_changed: del self.notes_changed[local_info["index"]]
                # Re-index notes_changed might be needed if not careful with tab removal order
                # For simplicity, assume removeTab handles index shifts correctly for subsequent calls if any.
                # A safer way is to collect indices and remove in reverse order.
                ui_changed = True
                # Optionally delete the local file: os.remove(self.get_note_filepath(note_name_to_delete))

        if ui_changed:
            logging.info("Notepad content updated from P2P sync.")
            if self.notepad_tabs.count() == 0: self.add_initial_notepad_tab()
            # Try to restore current tab if it still exists
            if current_tab_text_before_sync:
                restored_idx = -1
                clean_current_tab_name = current_tab_text_before_sync[:-2] if current_tab_text_before_sync.endswith(" *") else current_tab_text_before_sync
                for i in range(self.notepad_tabs.count()):
                    tab_text = self.notepad_tabs.tabText(i)
                    clean_tab_text = tab_text[:-2] if tab_text.endswith(" *") else tab_text
                    if clean_tab_text == clean_current_tab_name:
                        restored_idx = i
                        break
                if restored_idx != -1: self.notepad_tabs.setCurrentIndex(restored_idx)

    def handle_remote_notepad_rename(self, old_name, new_name):
        logging.info(f"P2P Rename: Handling remote rename from \'{old_name}\' to \'{new_name}\'.")
        found_index = -1
        for i in range(self.notepad_tabs.count()):
            tab_name_display = self.notepad_tabs.tabText(i)
            tab_name_actual = tab_name_display[:-2] if tab_name_display.endswith(" *") else tab_name_display
            if tab_name_actual == old_name: found_index = i; break
        if found_index != -1:
            # Check if new_name already exists (excluding the tab being renamed)
            new_name_exists_elsewhere = any(
                (self.notepad_tabs.tabText(j)[:-2] if self.notepad_tabs.tabText(j).endswith(" *") else self.notepad_tabs.tabText(j)) == new_name 
                for j in range(self.notepad_tabs.count()) if j != found_index
            )
            if new_name_exists_elsewhere:
                logging.warning(f"P2P Rename: Cannot apply remote rename. Target name \'{new_name}\' already exists locally.")
                # Conflict: maybe append a number or notify user.
                return
            was_unsaved = self.notepad_tabs.tabText(found_index).endswith(" *")
            new_display_name = new_name + (" *" if was_unsaved else "")
            self.notepad_tabs.setTabText(found_index, new_display_name)
            old_filepath = self.get_note_filepath(old_name)
            new_filepath = self.get_note_filepath(new_name)
            try:
                if os.path.exists(old_filepath):
                    os.rename(old_filepath, new_filepath)
                    logging.info(f"P2P Rename: Renamed note file \'{old_filepath}\' to \'{new_filepath}\'.")
                else: # If old file doesn't exist, save current content to new file name
                    widget = self.notepad_tabs.widget(found_index)
                    if isinstance(widget, QTextEdit):
                        with open(new_filepath, "w", encoding="utf-8") as f: f.write(widget.toPlainText())
            except Exception as e: logging.error(f"P2P Rename: Error renaming note file: {e}")
        else: logging.warning(f"P2P Rename: Note \'{old_name}\' not found locally for remote rename.")

    def handle_remote_notepad_delete(self, name_to_delete):
        logging.info(f"P2P Delete: Handling remote delete for note: \'{name_to_delete}\'.")
        found_index = -1
        for i in range(self.notepad_tabs.count()):
            tab_name_display = self.notepad_tabs.tabText(i)
            tab_name_actual = tab_name_display[:-2] if tab_name_display.endswith(" *") else tab_name_display
            if tab_name_actual == name_to_delete: found_index = i; break
        if found_index != -1:
            self.notepad_tabs.removeTab(found_index)
            if found_index in self.notes_changed: del self.notes_changed[found_index]
            # Re-index notes_changed
            new_notes_changed = {}
            for old_idx, status in self.notes_changed.items():
                if old_idx > found_index: new_notes_changed[old_idx - 1] = status
                elif old_idx < found_index: new_notes_changed[old_idx] = status
            self.notes_changed = new_notes_changed
            logging.info(f"P2P Delete: Removed local note tab \'{name_to_delete}\'.")
            filepath = self.get_note_filepath(name_to_delete)
            if os.path.exists(filepath):
                try: os.remove(filepath); logging.info(f"P2P Delete: Deleted local file: {filepath}")
                except Exception as e: logging.error(f"P2P Delete: Failed to delete local file {filepath}: {e}")
            if self.notepad_tabs.count() == 0: self.add_initial_notepad_tab()
        else: logging.warning(f"P2P Delete: Note \'{name_to_delete}\' not found locally for remote delete.")

    @Slot(str, int)
    def log_status(self, message, timeout=0): # (No changes from original)
        try:
            self.status_bar.showMessage(message, timeout)
            logging.debug(f"Status Bar: {message}")
        except Exception as e: logging.error(f"Error showing status message: {e}")

    @Slot(str, int, str)
    def update_peer_status_ui(self, address, port, status): # (No changes from original)
        logging.info(f"Peer Status Update: {address}:{port} -> {status}")
        self.log_status(f"Peer {address}:{port} is now {status}", 3000)

    # --- Auto Hide Methods (MODIFIED) ---
    @Slot(bool, bool)
    def toggle_auto_hide(self, checked, save_setting=True):
        self.auto_hide_enabled = checked
        if save_setting:
            self.settings.setValue("window/autoHide", checked)
        if checked:
            if not self.auto_hide_timer.isActive():
                self.auto_hide_timer.start()
            # Check immediately if we should hide, especially if turning on auto-hide
            self.check_mouse_position_for_auto_hide()
        else:
            if self.auto_hide_timer.isActive():
                self.auto_hide_timer.stop()
            if not self.isVisible(): # If auto-hide is turned off, ensure window is visible
                self.show_window()
        logging.info(f"Auto Hide toggled: {self.auto_hide_enabled}")

    @Slot()
    def check_mouse_position_for_auto_hide(self):
        if not self.auto_hide_enabled: return

        try:
            screen = QGuiApplication.primaryScreen()
            if not screen: return
            screen_geo = screen.availableGeometry() # Use availableGeometry to respect taskbars etc.
            mouse_pos = QCursor.pos() # Global mouse position

            edge_threshold = 10 # Pixels from the edge to trigger show
            is_near_right_edge = mouse_pos.x() >= (screen_geo.right() - edge_threshold) and \
                                 screen_geo.top() <= mouse_pos.y() <= screen_geo.bottom()

            if is_near_right_edge:
                if not self.isVisible():
                    logging.debug("Mouse near right edge, showing sidebar.")
                    self.show_window()
                    self.activateWindow() # Try to ensure it gets focus when shown by edge
            else: # Mouse is NOT near the right edge
                # Hide if window is visible, mouse is not over it, and it's not the active window.
                # The eventFilter handles deactivation, this is a fallback or for when mouse moves away.
                if self.isVisible() and not self.is_mouse_over_window and not self.isActiveWindow():
                    logging.debug("Mouse not near edge, not over window, window inactive -> hiding sidebar.")
                    self.hide_window()
                elif self.isVisible() and self.is_mouse_over_window and not self.isActiveWindow():
                    # If mouse is still over it, but it lost focus, leaveEvent + eventFilter should handle it.
                    # This timer check is a secondary check.
                    pass 

        except Exception as e:
            logging.warning(f"Could not check mouse position for auto-hide: {e}", exc_info=True)
            # Consider disabling auto-hide if this fails repeatedly
            # self.toggle_auto_hide(False)
            # QMessageBox.warning(self, "Auto-Hide Error", "Failed to monitor mouse position. Auto-hide disabled.")
            pass

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
    # Important: Prevent app from closing when last window is hidden (for tray functionality)
    app.setQuitOnLastWindowClosed(False)

    try:
        window = MainWindow()
        # window.show() # Visibility is handled in MainWindow.__init__ based on auto-hide
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
        except: pass
        sys.exit(1)

