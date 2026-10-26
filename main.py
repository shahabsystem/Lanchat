import sys, os, json, socket, threading, time, uuid, struct
from pathlib import Path
from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QLabel,
    QListWidget, QListWidgetItem, QTextEdit, QLineEdit, QPushButton, QFileDialog,
    QMessageBox, QInputDialog, QSystemTrayIcon, QMenu, QStyle
)

APP_NAME = "LanChat"
DISCOVERY_PORT = 39871
CHAT_PORT = 39872
DATA_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / APP_NAME
DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = DATA_DIR / "profile.json"

def load_profile():
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"name": socket.gethostname(), "avatar": "", "id": str(uuid.uuid4())}

def save_profile(profile):
    CONFIG_PATH.write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8")

class Bus(QObject):
    peer_seen = Signal(dict)
    incoming = Signal(dict)
    status = Signal(str)

class LanChat(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LanChat — پیام‌رسان شبکه محلی")
        self.setWindowIcon(QIcon(resource_path("lanchat.ico")))
        self.resize(1000, 650)
        self.bus = Bus()
        self.profile = load_profile()
        self.peers = {}
        self.selected_peer = None
        self.running = True
        self._build_ui()
        self.bus.peer_seen.connect(self.add_peer)
        self.bus.incoming.connect(self.receive_message)
        self.bus.status.connect(self.statusBar().showMessage)
        self._start_network()
        self._setup_tray()
        self.statusBar().showMessage("در حال جست‌وجوی کاربران شبکه محلی…")

    def _build_ui(self):
        self.setStyleSheet("""
            QMainWindow, QWidget { background: #171a21; color: #e8eaf0; font-size: 10pt; }
            QListWidget, QTextEdit, QLineEdit { background: #202530; border: 1px solid #343b4a; border-radius: 7px; padding: 7px; color: #f4f5f8; }
            QPushButton { background: #087fe7; color: white; border: 0; border-radius: 7px; padding: 9px 13px; }
            QPushButton:hover { background: #1597ff; }
            QLabel#heading { font-size: 15pt; font-weight: bold; }
        """)
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        sidebar = QVBoxLayout()
        heading = QLabel("LanChat")
        heading.setObjectName("heading")
        sidebar.addWidget(heading)
        self.profile_label = QLabel(f"👤  {self.profile.get('name', 'کاربر')}")
        self.profile_label.setWordWrap(True)
        sidebar.addWidget(self.profile_label)
        profile_btn = QPushButton("ویرایش پروفایل")
        profile_btn.clicked.connect(self.edit_profile)
        sidebar.addWidget(profile_btn)
        sidebar.addWidget(QLabel("کاربران شبکه"))
        self.user_list = QListWidget()
        self.user_list.itemClicked.connect(self.select_peer)
        sidebar.addWidget(self.user_list, 1)
        refresh_btn = QPushButton("جست‌وجوی دوباره")
        refresh_btn.clicked.connect(self.announce)
        sidebar.addWidget(refresh_btn)
        layout.addLayout(sidebar, 1)

        chat = QVBoxLayout()
        self.chat_title = QLabel("یک کاربر را انتخاب کنید")
        self.chat_title.setObjectName("heading")
        chat.addWidget(self.chat_title)
        self.messages = QTextEdit()
        self.messages.setReadOnly(True)
        chat.addWidget(self.messages, 1)
        row = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("پیام خود را بنویسید…")
        self.message_input.returnPressed.connect(self.send_text)
        row.addWidget(self.message_input, 1)
        send_btn = QPushButton("ارسال")
        send_btn.clicked.connect(self.send_text)
        row.addWidget(send_btn)
        file_btn = QPushButton("ارسال فایل")
        file_btn.clicked.connect(self.send_file_dialog)
        row.addWidget(file_btn)
        clip_btn = QPushButton("ارسال کلیپ‌بورد")
        clip_btn.clicked.connect(self.send_clipboard)
        row.addWidget(clip_btn)
        chat.addLayout(row)
        layout.addLayout(chat, 3)

    def _setup_tray(self):
        self.tray = QSystemTrayIcon(QIcon(resource_path("lanchat.ico")), self)
        if not self.tray.icon().isNull() is False:
            self.tray.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        menu = QMenu()
        show_action = QAction("نمایش LanChat", self)
        show_action.triggered.connect(self.showNormal)
        quit_action = QAction("خروج", self)
        quit_action.triggered.connect(self.close)
        menu.addAction(show_action)
        menu.addAction(quit_action)
        self.tray.setContextMenu(menu)
        self.tray.setToolTip("LanChat")
        self.tray.show()

    def _start_network(self):
        threading.Thread(target=self._discovery_listener, daemon=True).start()
        threading.Thread(target=self._tcp_listener, daemon=True).start()
        threading.Thread(target=self._announce_loop, daemon=True).start()

    def _announce_loop(self):
        while self.running:
            self.announce()
            time.sleep(5)

    def announce(self):
        try:
            payload = {"kind":"hello", "id": self.profile["id"],
                       "name": self.profile.get("name", socket.gethostname()),
                       "avatar": self.profile.get("avatar", ""), "port": CHAT_PORT,
                       "ts": time.time()}
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.sendto(data, ("255.255.255.255", DISCOVERY_PORT))
        except Exception as e:
            self.bus.status.emit(f"ارسال اعلان شبکه ناموفق بود: {e}")

    def _discovery_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("", DISCOVERY_PORT))
                s.settimeout(1)
                while self.running:
                    try:
                        data, addr = s.recvfrom(65535)
                        p = json.loads(data.decode("utf-8"))
                        if p.get("kind") != "hello" or p.get("id") == self.profile["id"]:
                            continue
                        p["ip"] = addr[0]
                        self.bus.peer_seen.emit(p)
                    except socket.timeout:
                        continue
                    except Exception:
                        continue
            except OSError as e:
                self.bus.status.emit(f"پورت کشف شبکه در دسترس نیست: {e}")

    def _tcp_listener(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("", CHAT_PORT))
                s.listen(20)
                s.settimeout(1)
                while self.running:
                    try:
                        conn, addr = s.accept()
                        threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True).start()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
            except OSError as e:
                self.bus.status.emit(f"پورت چت در دسترس نیست: {e}")

    def _recv_exact(self, conn, n):
        chunks = []
        while n:
            chunk = conn.recv(n)
            if not chunk:
                return None
            chunks.append(chunk)
            n -= len(chunk)
        return b"".join(chunks)

    def _handle_connection(self, conn, addr):
        try:
            with conn:
                raw_len = self._recv_exact(conn, 4)
                if not raw_len: return
                length = struct.unpack("!I", raw_len)[0]
                if length <= 0 or length > 1024 * 1024: return
                raw_header = self._recv_exact(conn, length)
                if not raw_header: return
                header = json.loads(raw_header.decode("utf-8"))
                if header.get("type") == "file":
                    name = Path(header.get("name", "received_file")).name
                    size = int(header.get("size", 0))
                    if size < 0 or size > 2 * 1024 * 1024 * 1024: return
                    target_dir = Path.home() / "Downloads" / "LanChat"
                    target_dir.mkdir(parents=True, exist_ok=True)
                    target = target_dir / name
                    n = 1
                    while target.exists():
                        target = target_dir / f"{Path(name).stem} ({n}){Path(name).suffix}"
                        n += 1
                    remaining = size
                    with open(target, "wb") as f:
                        while remaining:
                            chunk = conn.recv(min(65536, remaining))
                            if not chunk: break
                            f.write(chunk)
                            remaining -= len(chunk)
                    if remaining == 0:
                        self.bus.incoming.emit({"type":"system", "text":f"فایل دریافت شد: {target}"})
                elif header.get("type") == "text":
                    self.bus.incoming.emit({"type":"text", "text":header.get("text",""),
                                            "sender":header.get("sender","کاربر"),
                                            "ip":addr[0], "peer_id":header.get("sender_id","")})
        except Exception as e:
            self.bus.status.emit(f"خطا در دریافت: {e}")

    def add_peer(self, p):
        pid = p.get("id")
        if not pid or pid == self.profile["id"]: return
        self.peers[pid] = p
        for i in range(self.user_list.count()):
            item = self.user_list.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == pid:
                item.setText(f"🟢  {p.get('name','کاربر')}  ·  {p.get('ip','')}")
                return
        item = QListWidgetItem(f"🟢  {p.get('name','کاربر')}  ·  {p.get('ip','')}")
        item.setData(Qt.ItemDataRole.UserRole, pid)
        self.user_list.addItem(item)

    def select_peer(self, item):
        self.selected_peer = self.peers.get(item.data(Qt.ItemDataRole.UserRole))
        if self.selected_peer:
            self.chat_title.setText(f"گفت‌وگو با {self.selected_peer.get('name','کاربر')}")
            self.messages.append(f"<i>ارتباط مستقیم با {self.selected_peer.get('ip')}</i>")

    def _send_packet(self, peer, header, file_path=None):
        try:
            with socket.create_connection((peer["ip"], int(peer.get("port", CHAT_PORT))), timeout=5) as s:
                if file_path:
                    path = Path(file_path)
                    header.update({"type":"file","name":path.name,"size":path.stat().st_size})
                data = json.dumps(header, ensure_ascii=False).encode("utf-8")
                s.sendall(struct.pack("!I", len(data)) + data)
                if file_path:
                    with open(file_path, "rb") as f:
                        while True:
                            chunk = f.read(65536)
                            if not chunk: break
                            s.sendall(chunk)
            return True
        except Exception as e:
            QMessageBox.warning(self, "خطای ارسال", f"ارسال انجام نشد:\n{e}\n\nفایروال ویندوز و یکسان بودن شبکه را بررسی کنید.")
            return False

    def send_text(self):
        if not self.selected_peer:
            QMessageBox.information(self, "انتخاب کاربر", "ابتدا یک کاربر از فهرست انتخاب کنید.")
            return
        text = self.message_input.text().strip()
        if not text: return
        header = {"type":"text", "text":text, "sender":self.profile.get("name","کاربر"),
                  "sender_id":self.profile["id"]}
        if self._send_packet(self.selected_peer, header):
            self.messages.append(f"<b>من:</b> {text}")
            self.message_input.clear()

    def send_file_dialog(self):
        if not self.selected_peer:
            QMessageBox.information(self, "انتخاب کاربر", "ابتدا یک کاربر را انتخاب کنید."); return
        path, _ = QFileDialog.getOpenFileName(self, "انتخاب فایل")
        if path and self._send_packet(self.selected_peer, {"sender":self.profile.get("name","کاربر")}, path):
            self.messages.append(f"<i>فایل ارسال شد: {Path(path).name}</i>")

    def send_clipboard(self):
        text = QApplication.clipboard().text()
        if text:
            self.message_input.setText(text)
            self.send_text()
        else:
            QMessageBox.information(self, "کلیپ‌بورد", "فعلاً فقط متن کلیپ‌بورد پشتیبانی می‌شود.")

    def receive_message(self, msg):
        if msg.get("type") == "system":
            self.messages.append(f"<i>{msg.get('text','')}</i>")
            self.tray.showMessage("LanChat", msg.get("text",""))
        else:
            self.messages.append(f"<b>{msg.get('sender','کاربر')}:</b> {msg.get('text','')}")
            self.tray.showMessage(f"پیام از {msg.get('sender','کاربر')}", msg.get("text","")[:150])

    def edit_profile(self):
        name, ok = QInputDialog.getText(self, "پروفایل", "نام نمایشی:", text=self.profile.get("name",""))
        if ok and name.strip():
            self.profile["name"] = name.strip()
        path, _ = QFileDialog.getOpenFileName(self, "انتخاب عکس پروفایل", "", "Images (*.png *.jpg *.jpeg *.bmp)")
        if path:
            self.profile["avatar"] = path
        save_profile(self.profile)
        self.profile_label.setText(f"👤  {self.profile.get('name','کاربر')}")
        self.announce()

    def closeEvent(self, event):
        self.running = False
        try: self.tray.hide()
        except Exception: pass
        event.accept()

def resource_path(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)

def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(QIcon(resource_path("lanchat.ico")))
    window = LanChat()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
