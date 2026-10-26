import sys, os, json, socket, threading, time, uuid, struct, secrets, hashlib, hmac, logging
from pathlib import Path
from datetime import datetime
from PySide6.QtCore import Qt, Signal, QObject, QTimer, QUrl
from PySide6.QtGui import QAction, QIcon, QDesktopServices
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QLabel,
    QListWidget, QListWidgetItem, QTextEdit, QLineEdit, QPushButton, QFileDialog,
    QMessageBox, QInputDialog, QSystemTrayIcon, QMenu, QStyle, QDialog,
    QFormLayout, QCheckBox, QComboBox, QTabWidget, QTableWidget, QTableWidgetItem,
    QSpinBox, QGroupBox, QPlainTextEdit
)

APP_NAME = "LanChat"
HOST = "0.0.0.0"
PORT = 39872
MAX_PACKET = 8 * 1024 * 1024
DATA_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / APP_NAME
DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = DATA_DIR / "profile.json"
STATE_PATH = DATA_DIR / "manager_state.json"
LOG_PATH = DATA_DIR / "messages.txt"

DEFAULTS = {
    "name": socket.gethostname(), "id": str(uuid.uuid4()), "avatar": "",
    "role": "unpaired", "manager_host": "", "paired": False,
    "start_minimized": False, "close_to_tray": True, "run_at_startup": False,
    "save_messages": True, "notifications": True, "theme": "dark",
    "groups": [], "muted": False
}

def load_json(path, default):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else default.copy()
    except Exception:
        return default.copy()

def load_profile():
    p = DEFAULTS.copy()
    p.update(load_json(CONFIG_PATH, {}))
    if not p.get("id"): p["id"] = str(uuid.uuid4())
    return p

def save_profile(p):
    CONFIG_PATH.write_text(json.dumps(p, ensure_ascii=False, indent=2), encoding="utf-8")

def log_message(profile, text):
    if not profile.get("save_messages", True): return
    try:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {text}\n")
    except OSError:
        pass

def resource_path(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)

def pack(obj):
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    return struct.pack("!I", len(data)) + data

def recv_exact(sock, n):
    chunks = []
    while n:
        b = sock.recv(n)
        if not b: return None
        chunks.append(b); n -= len(b)
    return b"".join(chunks)

def recv_obj(sock):
    raw = recv_exact(sock, 4)
    if not raw: return None
    n = struct.unpack("!I", raw)[0]
    if n <= 0 or n > MAX_PACKET: return None
    body = recv_exact(sock, n)
    if not body: return None
    return json.loads(body.decode("utf-8"))

def rpc(host, request, timeout=4):
    with socket.create_connection((host, PORT), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(pack(request))
        return recv_obj(s)

class Bus(QObject):
    event = Signal(dict)
    status = Signal(str)

class ManagerServer:
    """Single-file central server. All admin actions are checked server-side."""
    def __init__(self, profile):
        self.profile = profile
        self.lock = threading.RLock()
        self.state = load_json(STATE_PATH, {})
        self.state.setdefault("manager_id", profile["id"])
        self.state.setdefault("pair_code_hash", "")
        self.state.setdefault("users", {})
        self.state.setdefault("groups", {})
        self.state.setdefault("messages", [])
        self.state.setdefault("settings", {"allow_files": True, "allow_user_messages": True})
        self.online = {}
        self.running = False
        self.server_socket = None
        if not self.state.get("pair_code_hash"):
            self.new_pair_code()
        self.save()

    def save(self):
        with self.lock:
            STATE_PATH.write_text(json.dumps(self.state, ensure_ascii=False, indent=2), encoding="utf-8")

    def new_pair_code(self):
        code = ''.join(secrets.choice("23456789ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(8))
        self.state["pair_code_hash"] = hashlib.sha256(code.encode()).hexdigest()
        self.current_pair_code = code
        self.save()
        return code

    def start(self):
        if self.running: return
        self.running = True
        threading.Thread(target=self._listen, daemon=True).start()

    def stop(self):
        self.running = False
        try:
            if self.server_socket: self.server_socket.close()
        except OSError: pass

    def _listen(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT)); s.listen(64); s.settimeout(1)
            self.server_socket = s
            while self.running:
                try: conn, addr = s.accept()
                except socket.timeout: continue
                except OSError: break
                threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
        except OSError as e:
            logging.exception("server")
            self.profile["_server_error"] = str(e)

    def _is_admin(self, req):
        return req.get("admin_token") == self.profile.get("admin_token") and bool(self.profile.get("admin_token"))

    def _handle(self, conn, addr):
        with conn:
            conn.settimeout(8)
            try:
                req = recv_obj(conn)
                if not isinstance(req, dict): return
                action = req.get("action")
                result = self.handle(req, addr)
                conn.sendall(pack(result))
            except Exception as e:
                try: conn.sendall(pack({"ok": False, "error": str(e)}))
                except Exception: pass

    def handle(self, req, addr):
        action = req.get("action")
        uid = str(req.get("user_id", ""))
        with self.lock:
            if action == "pair":
                code = str(req.get("code", "")).strip().upper()
                expected = self.state.get("pair_code_hash", "")
                if not expected or not hmac.compare_digest(hashlib.sha256(code.encode()).hexdigest(), expected):
                    return {"ok": False, "error": "کد اتصال نادرست است."}
                user = {"id": uid, "name": str(req.get("name", "کاربر"))[:80], "ip": addr[0],
                        "blocked": False, "muted": False, "groups": [], "joined": time.time()}
                self.state["users"][uid] = user
                self.online[uid] = time.time()
                # Rotate the pairing secret immediately so the same code cannot enroll another device.
                self.state["pair_code_hash"] = hashlib.sha256(secrets.token_urlsafe(32).encode()).hexdigest()
                self.save()
                return {"ok": True, "role": "client", "settings": self.public_settings(), "user": user}
            if action == "ping":
                user = self.state["users"].get(uid)
                if not user: return {"ok": False, "error": "این دستگاه جفت‌سازی نشده است."}
                if user.get("blocked"): return {"ok": False, "blocked": True, "error": "دسترسی این کاربر توسط مدیر مسدود شده است."}
                self.online[uid] = time.time()
                user["name"] = str(req.get("name", user.get("name", "کاربر")))[:80]
                user["ip"] = addr[0]
                self.save()
                pending = [m for m in self.state["messages"] if m.get("to") in (uid, "*") or
                           (m.get("to", "").startswith("group:") and m["to"][6:] in user.get("groups", []))]
                self.state["messages"] = [m for m in self.state["messages"] if m not in pending]
                self.save()
                return {"ok": True, "settings": self.public_settings(), "users": self.public_users(),
                        "groups": self.state["groups"], "messages": pending, "user": user}
            if action == "send":
                user = self.state["users"].get(uid)
                if not user: return {"ok": False, "error": "ابتدا باید جفت‌سازی شوید."}
                if user.get("blocked"): return {"ok": False, "error": "دسترسی شما مسدود است."}
                if user.get("muted") or (not self.state["settings"].get("allow_user_messages", True)):
                    return {"ok": False, "error": "ارسال پیام برای این حساب غیرفعال است."}
                target = str(req.get("to", ""))
                text = str(req.get("text", ""))[:12000]
                if not text.strip(): return {"ok": False, "error": "پیام خالی است."}
                if target == "*":
                    recipients = [k for k,v in self.state["users"].items() if not v.get("blocked") and k != uid]
                elif target.startswith("group:"):
                    group = self.state["groups"].get(target[6:], {})
                    recipients = [k for k in group.get("members", []) if k != uid]
                else:
                    recipients = [target] if target in self.state["users"] else []
                if not recipients: return {"ok": False, "error": "گیرنده‌ای برای این پیام پیدا نشد."}
                msg = {"id": str(uuid.uuid4()), "from": uid, "sender": user.get("name", "کاربر"),
                       "to": target, "text": text, "time": time.time()}
                for recipient in recipients:
                    item = msg.copy(); item["to"] = recipient
                    self.state["messages"].append(item)
                self.state["messages"] = self.state["messages"][-5000:]
                self.save()
                return {"ok": True, "sent": len(recipients)}
            if action == "admin":
                if not self._is_admin(req): return {"ok": False, "error": "احراز هویت مدیر ناموفق بود."}
                op = req.get("op")
                if op == "snapshot":
                    return {"ok": True, "users": self.public_users(), "groups": self.state["groups"],
                            "settings": self.state["settings"], "online": list(self.online.keys())}
                if op == "user":
                    target = self.state["users"].get(str(req.get("target", "")))
                    if not target: return {"ok": False, "error": "کاربر پیدا نشد."}
                    field = req.get("field")
                    if field not in ("blocked", "muted"): return {"ok": False, "error": "عملیات نامعتبر"}
                    target[field] = bool(req.get("value")); self.save()
                    return {"ok": True}
                if op == "group":
                    name = str(req.get("name", "")).strip()[:60]
                    if not name: return {"ok": False, "error": "نام گروه لازم است."}
                    gid = str(req.get("group_id") or uuid.uuid4().hex[:10])
                    self.state["groups"][gid] = {"name": name, "members": list(dict.fromkeys(req.get("members", [])))}
                    for u in self.state["users"].values():
                        u["groups"] = [g for g in u.get("groups", []) if g != gid]
                        if u["id"] in self.state["groups"][gid]["members"]: u["groups"].append(gid)
                    self.save(); return {"ok": True, "group_id": gid}
                if op == "settings":
                    self.state["settings"]["allow_user_messages"] = bool(req.get("allow_user_messages", True))
                    self.save(); return {"ok": True}
                if op == "broadcast":
                    text = str(req.get("text", ""))[:12000]
                    if not text.strip(): return {"ok": False, "error": "متن پیام خالی است."}
                    for uid2, user2 in self.state["users"].items():
                        if not user2.get("blocked"):
                            self.state["messages"].append({"id":str(uuid.uuid4()),"from":"ADMIN","sender":"مدیر",
                                "to":uid2,"text":text,"time":time.time()})
                    self.save(); return {"ok": True}
                if op == "paircode":
                    code = self.new_pair_code()
                    return {"ok": True, "code": code}
                return {"ok": False, "error": "عملیات مدیریتی ناشناخته است."}
        return {"ok": False, "error": "درخواست ناشناخته است."}

    def public_settings(self):
        return {"allow_user_messages": self.state["settings"].get("allow_user_messages", True),
                "groups": self.state["groups"], "manager_id": self.profile["id"]}

    def public_users(self):
        return list(self.state["users"].values())

class SettingsDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.w = parent
        self.setWindowTitle("تنظیمات LanChat")
        self.resize(520, 420)
        root = QVBoxLayout(self)
        tabs = QTabWidget()
        general = QWidget(); form = QFormLayout(general)
        self.name = QLineEdit(self.w.profile.get("name", ""))
        form.addRow("نام نمایشی:", self.name)
        self.start_min = QCheckBox("اجرای برنامه بدون نمایش پنجره اصلی")
        self.start_min.setChecked(self.w.profile.get("start_minimized", False)); form.addRow(self.start_min)
        self.close_tray = QCheckBox("با زدن ضربدر به System Tray منتقل شود")
        self.close_tray.setChecked(self.w.profile.get("close_to_tray", True)); form.addRow(self.close_tray)
        self.startup = QCheckBox("اجرای خودکار با شروع ویندوز")
        self.startup.setChecked(self.w.profile.get("run_at_startup", False)); form.addRow(self.startup)
        self.save_msgs = QCheckBox("ذخیره پیام‌های ارسالی و دریافتی در فایل متنی")
        self.save_msgs.setChecked(self.w.profile.get("save_messages", True)); form.addRow(self.save_msgs)
        self.notifs = QCheckBox("نمایش اعلان پیام‌ها")
        self.notifs.setChecked(self.w.profile.get("notifications", True)); form.addRow(self.notifs)
        self.avatar = QLineEdit(self.w.profile.get("avatar", ""))
        avatar_row = QWidget(); avl = QHBoxLayout(avatar_row); avl.setContentsMargins(0,0,0,0); avl.addWidget(self.avatar)
        pick = QPushButton("انتخاب"); pick.clicked.connect(self.pick_avatar); avl.addWidget(pick)
        form.addRow("عکس پروفایل:", avatar_row)
        tabs.addTab(general, "عمومی")
        role = QWidget(); rl = QVBoxLayout(role)
        if self.w.profile.get("role") == "manager":
            rl.addWidget(QLabel("این رایانه مدیر شبکه است. پنل مدیریت در پنجره اصلی موجود است."))
            self.allow_messages = QCheckBox("اجازه ارسال پیام توسط کاربران عادی")
            self.allow_messages.setChecked(self.w.manager_state.state["settings"].get("allow_user_messages", True))
            rl.addWidget(self.allow_messages)
            code_btn = QPushButton("تولید کد جفت‌سازی جدید")
            code_btn.clicked.connect(self.new_code); rl.addWidget(code_btn)
            self.code_label = QLabel("کد فعلی فقط هنگام تولید نمایش داده می‌شود."); rl.addWidget(self.code_label)
        else:
            if not self.w.profile.get("paired") and self.w.profile.get("role") != "client":
                rl.addWidget(QLabel("این رایانه را برای اولین بار به‌عنوان مدیر شبکه راه‌اندازی کنید، یا به مدیر موجود متصل شوید."))
                manager_btn = QPushButton("راه‌اندازی این رایانه به‌عنوان مدیر")
                manager_btn.clicked.connect(self.make_manager); rl.addWidget(manager_btn)
            rl.addWidget(QLabel("اتصال به رایانه مدیر"))
            self.host = QLineEdit(self.w.profile.get("manager_host", "")); self.host.setPlaceholderText("IP رایانه مدیر، مثلاً 192.168.1.10")
            self.code = QLineEdit(); self.code.setPlaceholderText("کد جفت‌سازی ۸ کاراکتری")
            rl.addWidget(self.host); rl.addWidget(self.code)
            pair_btn = QPushButton("اتصال و جفت‌سازی با مدیر"); pair_btn.clicked.connect(self.pair); rl.addWidget(pair_btn)
            if self.w.profile.get("paired"):
                rl.addWidget(QLabel("این دستگاه قبلاً جفت‌سازی شده است. نقش مدیر از این صفحه قابل فعال‌سازی نیست."))
        tabs.addTab(role, "شبکه و نقش")

        support = QWidget()
        support_layout = QVBoxLayout(support)
        support_layout.addWidget(QLabel("اگر LanChat برایتان مفید است، می‌توانید از توسعه‌دهنده حمایت کنید."))
        coffee_btn = QPushButton("☕ یه قهوه مهمونم کن")
        coffee_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://coffeebede.com/shahabsystem")))
        support_layout.addWidget(coffee_btn)
        reymit_btn = QPushButton("💙 نقدی خوشحالم کن")
        reymit_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://reymit.ir/shahabsystem")))
        support_layout.addWidget(reymit_btn)
        support_layout.addStretch(1)
        tabs.addTab(support, "حمایت از توسعه‌دهنده")

        root.addWidget(tabs)
        buttons = QHBoxLayout()
        save_btn = QPushButton("ذخیره")
        save_btn.clicked.connect(self.save)
        buttons.addWidget(save_btn)
        close_btn = QPushButton("بستن")
        close_btn.clicked.connect(self.accept)
        buttons.addWidget(close_btn)
        root.addLayout(buttons)

    def make_manager(self):
        answer = QMessageBox.question(self, "راه‌اندازی مدیر", "این رایانه مدیر اصلی این شبکه شود؟ فقط یک رایانه را مدیر اصلی انتخاب کنید.")
        if answer != QMessageBox.StandardButton.Yes: return
        self.w.profile.update({"role":"manager", "paired":False, "manager_host":""})
        save_profile(self.w.profile)
        QMessageBox.information(self, "مدیر شبکه", "نقش مدیر ذخیره شد. برای فعال‌شدن سرویس، LanChat را ببندید و دوباره اجرا کنید.")
        self.accept()

    def pick_avatar(self):
        p, _ = QFileDialog.getOpenFileName(self, "انتخاب تصویر", "", "Images (*.png *.jpg *.jpeg *.bmp)")
        if p: self.avatar.setText(p)

    def new_code(self):
        result = self.w.admin_call("paircode")
        if result.get("ok"):
            self.code_label.setText(f"کد اتصال جدید: {result['code']}  (آن را فقط به کاربران مورد اعتماد بدهید)")
            QMessageBox.information(self, "کد جفت‌سازی", result["code"])

    def pair(self):
        host, code = self.host.text().strip(), self.code.text().strip().upper()
        if not host or len(code) != 8:
            QMessageBox.warning(self, "اطلاعات ناقص", "IP مدیر و کد ۸ کاراکتری را وارد کنید."); return
        try:
            result = rpc(host, {"action":"pair", "user_id":self.w.profile["id"], "name":self.name.text().strip(), "code":code})
        except Exception as e:
            QMessageBox.warning(self, "اتصال ناموفق", f"اتصال به مدیر انجام نشد: {e}"); return
        if not result.get("ok"):
            QMessageBox.warning(self, "جفت‌سازی ناموفق", result.get("error", "خطا")); return
        self.w.profile.update({"role":"client", "paired":True, "manager_host":host})
        save_profile(self.w.profile)
        QMessageBox.information(self, "موفق", "دستگاه جفت‌سازی شد. برای اعمال کامل تنظیمات، برنامه را دوباره باز کنید.")
        self.accept()

    def save(self):
        p = self.w.profile
        p.update({"name": self.name.text().strip() or socket.gethostname(),
                  "avatar": self.avatar.text().strip(), "start_minimized": self.start_min.isChecked(),
                  "close_to_tray": self.close_tray.isChecked(), "run_at_startup": self.startup.isChecked(),
                  "save_messages": self.save_msgs.isChecked(), "notifications": self.notifs.isChecked()})
        if p["role"] == "manager":
            self.w.admin_call("settings", allow_user_messages=self.allow_messages.isChecked())
        try: self.w.apply_startup_setting()
        except Exception as e: QMessageBox.warning(self, "شروع خودکار", str(e))
        save_profile(p)
        self.w.refresh_profile()
        self.accept()

class LanChat(QMainWindow):
    def __init__(self):
        super().__init__()
        self.profile = load_profile()
        self.bus = Bus()
        self.peers = {}
        self.selected_id = None
        self.manager_state = None
        self.admin_token = None
        self.profile["admin_token"] = ""
        self.running = True
        self.setWindowTitle("LanChat — پیام‌رسان شبکه محلی")
        self.setWindowIcon(QIcon(resource_path("lanchat.ico")))
        self.resize(1050, 680)
        self._build_ui()
        self._setup_tray()
        self.bus.event.connect(self.handle_event)
        self.bus.status.connect(self.statusBar().showMessage)
        if self.profile.get("role") == "manager":
            self._start_manager()
        elif self.profile.get("paired"):
            self._start_client_poll()
        self.timer = QTimer(self); self.timer.timeout.connect(self.refresh_online); self.timer.start(5000)
        self.statusBar().showMessage("برای شروع، از تنظیمات نقش مدیر یا اتصال به مدیر را انتخاب کنید.")

    def _build_ui(self):
        self.setStyleSheet("""
        QMainWindow,QWidget {background:#171a21;color:#e8eaf0;font-size:10pt}
        QListWidget,QTextEdit,QLineEdit,QPlainTextEdit,QComboBox,QTableWidget {background:#202530;border:1px solid #343b4a;border-radius:6px;padding:6px;color:#f4f5f8}
        QPushButton {background:#087fe7;color:white;border:0;border-radius:6px;padding:8px 12px}
        QPushButton:hover {background:#1597ff}
        QTabWidget::pane {border:1px solid #343b4a}
        """)
        root = QWidget(); self.setCentralWidget(root); layout = QHBoxLayout(root)
        side = QVBoxLayout()
        title = QLabel("LanChat"); title.setStyleSheet("font-size:18pt;font-weight:bold"); side.addWidget(title)
        self.profile_label = QLabel(); side.addWidget(self.profile_label)
        pbtn = QPushButton("تنظیمات"); pbtn.clicked.connect(self.open_settings); side.addWidget(pbtn)
        self.role_label = QLabel(); side.addWidget(self.role_label)
        self.user_list = QListWidget(); self.user_list.itemClicked.connect(self.select_user); side.addWidget(QLabel("کاربران / مقصد")); side.addWidget(self.user_list,1)
        self.target = QComboBox(); self.target.addItem("همه کاربران آنلاین", "*"); side.addWidget(self.target)
        self.group_target = QComboBox(); self.group_target.addItem("ارسال به گروه…", ""); side.addWidget(self.group_target)
        side.addWidget(QLabel("متن پیام گروهی یا همگانی را از انتخاب مقصد ارسال کنید."))
        layout.addLayout(side, 1)
        chat = QVBoxLayout()
        self.chat_title = QLabel("پیام‌رسان شبکه داخلی"); self.chat_title.setStyleSheet("font-size:14pt;font-weight:bold"); chat.addWidget(self.chat_title)
        self.messages = QTextEdit(); self.messages.setReadOnly(True); chat.addWidget(self.messages,1)
        row = QHBoxLayout(); self.message_input = QLineEdit(); self.message_input.setPlaceholderText("پیام خود را بنویسید…")
        self.message_input.returnPressed.connect(self.send_text); row.addWidget(self.message_input,1)
        send = QPushButton("ارسال"); send.clicked.connect(self.send_text); row.addWidget(send)
        fileb = QPushButton("ارسال فایل"); fileb.clicked.connect(self.send_file); row.addWidget(fileb)
        chat.addLayout(row); layout.addLayout(chat,3)
        self.admin_tabs = QTabWidget()
        self.admin_users = QTableWidget(0,5); self.admin_users.setHorizontalHeaderLabels(["نام","IP","مسدود","ارسال پیام","شناسه"])
        self.admin_users.cellDoubleClicked.connect(self.toggle_user_restriction)
        self.admin_tabs.addTab(self.admin_users,"مدیریت کاربران")
        self.admin_groups = QPlainTextEdit(); self.admin_groups.setPlaceholderText("یک گروه در هر خط: نام گروه = شناسه۱,شناسه۲")
        group_page = QWidget(); gl = QVBoxLayout(group_page); gl.addWidget(QLabel("شناسه کاربران را از جدول مدیریت کاربران کپی کنید. قالب هر خط: نام گروه = شناسه۱,شناسه۲"))
        gl.addWidget(self.admin_groups)
        save_groups = QPushButton("ذخیره گروه‌ها"); save_groups.clicked.connect(self.save_groups); gl.addWidget(save_groups)
        self.admin_tabs.addTab(group_page,"گروه‌ها")
        self.admin_broadcast = QPlainTextEdit(); self.admin_broadcast.setPlaceholderText("پیام اطلاع‌رسانی مدیر به همه کاربران")
        bpage = QWidget(); bl = QVBoxLayout(bpage); bl.addWidget(self.admin_broadcast); bb = QPushButton("ارسال اطلاعیه مدیر"); bb.clicked.connect(self.admin_broadcast_send); bl.addWidget(bb)
        self.admin_tabs.addTab(bpage,"اطلاعیه")
        self.admin_tabs.hide()
        layout.addWidget(self.admin_tabs,2)
        self.refresh_profile()

    def _setup_tray(self):
        self.tray = QSystemTrayIcon(QIcon(resource_path("lanchat.ico")), self)
        if self.tray.icon().isNull(): self.tray.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        menu = QMenu()
        show = QAction("نمایش LanChat", self); show.triggered.connect(self.showNormal)
        settings = QAction("تنظیمات", self); settings.triggered.connect(self.open_settings)
        quit_action = QAction("خروج کامل", self); quit_action.triggered.connect(self.quit_app)
        menu.addAction(show); menu.addAction(settings); menu.addSeparator(); menu.addAction(quit_action)
        self.tray.setContextMenu(menu); self.tray.setToolTip("LanChat"); self.tray.activated.connect(self.tray_activated); self.tray.show()

    def tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick: self.showNormal(); self.activateWindow()

    def _start_manager(self):
        self.manager_state = ManagerServer(self.profile)
        if not self.profile.get("admin_token"):
            self.profile["admin_token"] = secrets.token_urlsafe(32); save_profile(self.profile)
        self.manager_state.profile["admin_token"] = self.profile["admin_token"]
        self.admin_tabs.show(); self.role_label.setText("نقش: مدیر شبکه")
        self.manager_state.start()
        self.statusBar().showMessage("مدیر فعال است. پورت TCP 39872 را در فایروال مجاز کنید.")
        self.refresh_admin()

    def _start_client_poll(self):
        self.role_label.setText("نقش: کاربر عادی")
        self.client_timer = QTimer(self); self.client_timer.timeout.connect(self.poll_manager); self.client_timer.start(2500)
        QTimer.singleShot(500, self.poll_manager)

    def poll_manager(self):
        host = self.profile.get("manager_host", "")
        if not host or not self.profile.get("paired"): return
        try:
            result = rpc(host, {"action":"ping", "user_id":self.profile["id"], "name":self.profile.get("name","کاربر")})
            if not result.get("ok"):
                self.bus.status.emit(result.get("error","اتصال مدیر برقرار نیست")); return
            self.profile["_manager_settings"] = result.get("settings", {})
            save_profile(self.profile)
            for msg in result.get("messages", []):
                self.bus.event.emit({"kind":"message", **msg})
            users = result.get("users", [])
            self.peers = {u["id"]:u for u in users if u.get("id") != self.profile["id"]}
            self.bus.event.emit({"kind":"users", "users":users, "groups":result.get("groups",{})})
        except Exception as e:
            self.bus.status.emit(f"اتصال به مدیر برقرار نیست: {e}")

    def refresh_online(self):
        if self.profile.get("role") == "manager" and self.manager_state:
            self.refresh_admin()

    def handle_event(self, event):
        if event.get("kind") == "message":
            sender = event.get("sender","کاربر"); body = event.get("text","")
            stamp = datetime.fromtimestamp(event.get("time", time.time())).strftime("%H:%M:%S")
            self.messages.append(f"[{stamp}] <b>{sender}:</b> {body}")
            log_message(self.profile, f"{sender}: {body}")
            if self.profile.get("notifications", True) and not self.isVisible():
                self.tray.showMessage(f"LanChat — {sender}", body[:200], QSystemTrayIcon.MessageIcon, 5000)
        elif event.get("kind") == "users":
            self.user_list.clear()
            for u in event.get("users", []):
                if u.get("id") == self.profile["id"]: continue
                if u.get("blocked"): continue
                item = QListWidgetItem(f"👤 {u.get('name','کاربر')} · {u.get('ip','')}")
                item.setData(Qt.ItemDataRole.UserRole, u["id"]); self.user_list.addItem(item)
            self.group_target.clear(); self.group_target.addItem("ارسال به گروه…","")
            for gid, g in event.get("groups", {}).items(): self.group_target.addItem(g.get("name",gid), gid)

    def select_user(self, item):
        self.selected_id = item.data(Qt.ItemDataRole.UserRole)
        self.target.setCurrentIndex(max(0, self.target.findData(self.selected_id)))
        self.chat_title.setText("گفت‌وگو با " + item.text())

    def send_text(self):
        text = self.message_input.text().strip()
        if not text: return
        if self.profile.get("role") == "manager":
            target = self.group_target.currentData()
            target = "group:" + target if target else (self.selected_id or self.target.currentData() or "*")
            # manager messages are sent through a trusted local admin call
            if target == "*": result = self.admin_call("broadcast", text=text)
            else:
                result = self.manager_send(target, text)
        else:
            target = self.selected_id or self.target.currentData() or "*"
            try: result = rpc(self.profile["manager_host"], {"action":"send","user_id":self.profile["id"],"to":target,"text":text})
            except Exception as e: result = {"ok":False,"error":str(e)}
        if result.get("ok"):
            self.messages.append(f"<b>من:</b> {text}"); log_message(self.profile, f"من: {text}")
            self.message_input.clear()
        else: QMessageBox.warning(self, "ارسال ناموفق", result.get("error","خطا در ارسال پیام"))

    def manager_send(self, target, text):
        # manager is locally trusted; directly append to central message queue.
        with self.manager_state.lock:
            if target.startswith("group:"):
                gid = target[6:]; group = self.manager_state.state["groups"].get(gid, {})
                recipients = group.get("members", [])
            else: recipients = [target] if target in self.manager_state.state["users"] else []
            for uid in recipients:
                self.manager_state.state["messages"].append({"id":str(uuid.uuid4()),"from":"MANAGER","sender":self.profile["name"],"to":uid,"text":text,"time":time.time()})
            self.manager_state.save()
        return {"ok": bool(recipients), "error":"گیرنده‌ای پیدا نشد."}

    def send_file(self):
        QMessageBox.information(self, "ارسال فایل", "انتقال فایل در این نسخه از طریق سرور مرکزی فعال نشده است. در نسخه بعدی باید با تأیید گیرنده و محدودیت حجم اضافه شود.")

    def admin_call(self, op, **kwargs):
        if self.profile.get("role") != "manager" or not self.manager_state: return {"ok":False,"error":"این عملیات فقط برای مدیر است."}
        return self.manager_state.handle({"action":"admin","op":op,"admin_token":self.profile.get("admin_token"),**kwargs}, ("127.0.0.1", 0))

    def refresh_admin(self):
        if not self.manager_state: return
        snap = self.admin_call("snapshot")
        if not snap.get("ok"): return
        users = snap.get("users", []); online = set(snap.get("online", []))
        self.admin_users.setRowCount(len(users))
        for r,u in enumerate(users):
            vals = [u.get("name",""),u.get("ip",""),"آنلاین" if u["id"] in online and time.time()-self.manager_state.online.get(u["id"],0)<12 else "آفلاین",
                    "محدود" if u.get("muted") else "مجاز",u.get("id","")]
            for c,v in enumerate(vals): self.admin_users.setItem(r,c,QTableWidgetItem(str(v)))
        self.admin_users.resizeColumnsToContents()

    def toggle_user_restriction(self, row, column):
        if not self.manager_state or row >= self.admin_users.rowCount(): return
        id_item = self.admin_users.item(row, 4)
        if not id_item: return
        uid = id_item.text()
        choice, ok = QInputDialog.getItem(self, "مدیریت کاربر", "عملیات را انتخاب کنید:",
                                          ["مسدود/رفع مسدودی", "بستن/بازکردن ارسال پیام"], 0, False)
        if not ok: return
        field = "blocked" if choice.startswith("مسدود") else "muted"
        current = self.manager_state.state["users"].get(uid, {}).get(field, False)
        result = self.admin_call("user", target=uid, field=field, value=not current)
        if result.get("ok"): self.refresh_admin()
        else: QMessageBox.warning(self, "خطا", result.get("error", "عملیات انجام نشد"))

    def save_groups(self):
        if not self.manager_state: return
        existing = {v.get("name"): k for k,v in self.manager_state.state["groups"].items()}
        created = 0
        for line in self.admin_groups.toPlainText().splitlines():
            if "=" not in line: continue
            name, raw_members = line.split("=", 1)
            name = name.strip()
            members = [x.strip() for x in raw_members.split(",") if x.strip()]
            if not name: continue
            result = self.admin_call("group", name=name, members=members, group_id=existing.get(name))
            if result.get("ok"): created += 1
        QMessageBox.information(self, "گروه‌ها", f"{created} گروه ذخیره شد.")
        self.refresh_admin()

    def admin_broadcast_send(self):
        text = self.admin_broadcast.toPlainText().strip()
        if not text: return
        result = self.admin_call("broadcast", text=text)
        if result.get("ok"):
            self.admin_broadcast.clear(); QMessageBox.information(self,"اطلاعیه","پیام در صف ارسال قرار گرفت.")
        else: QMessageBox.warning(self,"خطا",result.get("error","خطا"))

    def open_settings(self):
        dlg = SettingsDialog(self); dlg.exec()

    def refresh_profile(self):
        self.profile_label.setText(f"👤 {self.profile.get('name','کاربر')}")
        role = self.profile.get("role")
        self.role_label.setText("نقش: مدیر" if role == "manager" else ("نقش: کاربر عادی" if self.profile.get("paired") else "نقش: تنظیم‌نشده"))

    def apply_startup_setting(self):
        if sys.platform != "win32": return
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            if self.profile.get("run_at_startup"):
                exe = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(sys.argv[0])
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, f'"{exe}" --minimized')
            else:
                try: winreg.DeleteValue(key, APP_NAME)
                except FileNotFoundError: pass

    def showEvent(self, event):
        super().showEvent(event)

    def closeEvent(self, event):
        if self.profile.get("close_to_tray", True) and self.tray.isVisible() and not getattr(self, "_really_quit", False):
            event.ignore(); self.hide(); self.tray.showMessage("LanChat","برنامه در کنار ساعت فعال است.",QSystemTrayIcon.MessageIcon,2500)
        else:
            event.accept(); self.quit_app()

    def quit_app(self):
        self._really_quit = True; self.running = False
        if self.manager_state: self.manager_state.stop()
        self.tray.hide(); QApplication.quit()

def main():
    app = QApplication(sys.argv); app.setApplicationName(APP_NAME); app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(QIcon(resource_path("lanchat.ico")))
    window = LanChat()
    if "--minimized" in sys.argv or window.profile.get("start_minimized", False): window.hide()
    else: window.show()
    sys.exit(app.exec())

if __name__ == "__main__": main()
