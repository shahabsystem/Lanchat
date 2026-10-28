import sys, os, json, socket, threading, time, uuid, struct, logging
from pathlib import Path
from datetime import datetime
from PySide6.QtCore import Qt, Signal, QObject, QTimer
from PySide6.QtGui import QIcon, QDesktopServices
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QListWidget, QListWidgetItem, QTextEdit, QLineEdit, QPushButton, QMessageBox,
    QSystemTrayIcon, QMenu, QStyle, QDialog, QFormLayout, QCheckBox, QComboBox)

APP_NAME = 'LanChat'
APP_VERSION = '1.2.0'
DEVELOPER_EMAIL = 'hamedmohammadinikche@gmail.com'
TCP_PORT = 39872
UDP_PORT = 39873
BEACON = 'LANCHAT_PEER_V3'
ONLINE_TIMEOUT = 12
MAX_PACKET = 2 * 1024 * 1024
DATA_DIR = Path(os.environ.get('APPDATA', str(Path.home()))) / APP_NAME
DATA_DIR.mkdir(parents=True, exist_ok=True)
PROFILE_PATH = DATA_DIR / 'profile.json'
LOG_PATH = DATA_DIR / 'messages.txt'


def load_profile():
    try: p = json.loads(PROFILE_PATH.read_text(encoding='utf-8'))
    except Exception: p = {}
    p.setdefault('id', str(uuid.uuid4()))
    p.setdefault('name', socket.gethostname())
    p.setdefault('theme', 'dark')
    p.setdefault('save_messages', True)
    p.setdefault('notifications', True)
    p.setdefault('close_to_tray', False)
    return p


def save_profile(profile):
    PROFILE_PATH.write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding='utf-8')


def save_message(line):
    try:
        with LOG_PATH.open('a', encoding='utf-8') as f:
            f.write(f'[{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] {line}\n')
    except OSError:
        logging.exception('Could not save message')


def pack(obj):
    data = json.dumps(obj, ensure_ascii=False).encode('utf-8')
    return struct.pack('!I', len(data)) + data


def recv_exact(sock, count):
    out = bytearray()
    while len(out) < count:
        chunk = sock.recv(count-len(out))
        if not chunk: return None
        out.extend(chunk)
    return bytes(out)


def recv_obj(sock):
    header = recv_exact(sock, 4)
    if not header: return None
    size = struct.unpack('!I', header)[0]
    if size < 1 or size > MAX_PACKET: return None
    body = recv_exact(sock, size)
    if not body: return None
    try: return json.loads(body.decode('utf-8'))
    except (ValueError, UnicodeDecodeError): return None


def broadcast_targets():
    targets = {'255.255.255.255'}
    try:
        import psutil
        for items in psutil.net_if_addrs().values():
            for a in items:
                if a.family == socket.AF_INET and a.broadcast and a.address and not a.address.startswith(('127.', '169.254.')):
                    targets.add(a.broadcast)
    except Exception: pass
    return sorted(targets)


class Events(QObject):
    peers_changed = Signal()
    message_received = Signal(dict)
    status = Signal(str)


class PeerNetwork:
    """Decentralized LAN peer: each running client advertises and accepts direct messages."""
    def __init__(self, profile, events):
        self.profile, self.events = profile, events
        self.lock = threading.RLock()
        self.peers = {}  # stable peer id -> {name, ip, last_seen}
        self.running = False
        self.udp = None
        self.tcp = None

    def start(self):
        if self.running: return
        self.running = True
        threading.Thread(target=self._tcp_server, daemon=True).start()
        threading.Thread(target=self._udp_server, daemon=True).start()
        threading.Thread(target=self._beacon_loop, daemon=True).start()

    def stop(self):
        self.running = False
        for s in (self.udp, self.tcp):
            try:
                if s: s.close()
            except OSError: pass

    def _tcp_server(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('', TCP_PORT)); s.listen(40); s.settimeout(1)
            self.tcp = s
            self.events.status.emit(f'در حال دریافت پیام روی پورت {TCP_PORT}')
            while self.running:
                try: conn, addr = s.accept()
                except socket.timeout: continue
                except OSError: break
                threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True).start()
        except OSError as e:
            self.events.status.emit(f'خطای شبکه: {e}. شاید برنامه روی این رایانه قبلاً اجرا شده باشد.')

    def _handle_connection(self, conn, addr):
        with conn:
            conn.settimeout(8)
            try:
                obj = recv_obj(conn)
                if not isinstance(obj, dict): return
                if obj.get('kind') == 'message' and obj.get('to') == self.profile['id']:
                    sender = str(obj.get('from', ''))
                    if not sender or sender == self.profile['id']: return
                    message = {'kind':'message', 'from':sender,
                        'name':str(obj.get('name','کاربر'))[:64], 'text':str(obj.get('text',''))[:12000],
                        'time':str(obj.get('time','')), 'ip':addr[0]}
                    self._update_peer(sender, message['name'], addr[0])
                    self.events.message_received.emit(message)
                    conn.sendall(pack({'ok': True}))
            except (OSError, ValueError, UnicodeDecodeError): pass

    def _udp_server(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_BROADCAST'): s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.bind(('', UDP_PORT)); s.settimeout(1)
            self.udp = s
            while self.running:
                try: data, addr = s.recvfrom(4096)
                except socket.timeout: self._expire_peers(); continue
                except OSError: break
                try: obj = json.loads(data.decode('utf-8'))
                except Exception: continue
                if not isinstance(obj, dict) or obj.get('kind') != BEACON: continue
                peer_id = str(obj.get('id',''))
                if not peer_id or peer_id == self.profile['id']: continue
                name = str(obj.get('name','کاربر'))[:64]
                ip = addr[0]
                self._update_peer(peer_id, name, ip)
                # Unicast reply helps peers on networks where broadcast delivery is asymmetric.
                try:
                    reply = self._beacon_data()
                    s.sendto(json.dumps(reply, ensure_ascii=False).encode('utf-8'), addr)
                except OSError: pass
        except OSError as e:
            self.events.status.emit(f'کشف خودکار شبکه در دسترس نیست: {e}')

    def _beacon_data(self):
        return {'kind':BEACON, 'id':self.profile['id'], 'name':str(self.profile.get('name') or socket.gethostname())[:64], 'port':TCP_PORT, 'time':time.time()}

    def _beacon_loop(self):
        while self.running:
            s = self.udp
            if s:
                payload = json.dumps(self._beacon_data(), ensure_ascii=False).encode('utf-8')
                for target in broadcast_targets():
                    try: s.sendto(payload, (target, UDP_PORT))
                    except OSError: pass
            self._expire_peers()
            for _ in range(30):
                if not self.running: break
                time.sleep(0.1)

    def _update_peer(self, peer_id, name, ip):
        changed = False
        with self.lock:
            old = self.peers.get(peer_id)
            if not old or old.get('name') != name or old.get('ip') != ip: changed = True
            self.peers[peer_id] = {'id':peer_id, 'name':name, 'ip':ip, 'last_seen':time.monotonic()}
        if changed: self.events.peers_changed.emit()

    def _expire_peers(self):
        now = time.monotonic(); changed = False
        with self.lock:
            for pid in list(self.peers):
                if now - self.peers[pid]['last_seen'] > ONLINE_TIMEOUT:
                    del self.peers[pid]; changed = True
        if changed: self.events.peers_changed.emit()

    def get_peers(self):
        with self.lock: return [dict(p) for p in self.peers.values()]

    def send_message(self, peer, text):
        request = {'kind':'message', 'from':self.profile['id'], 'to':peer['id'],
                   'name':str(self.profile.get('name') or socket.gethostname())[:64],
                   'text':text, 'time':datetime.now().isoformat(timespec='seconds')}
        with socket.create_connection((peer['ip'], TCP_PORT), timeout=3) as s:
            s.settimeout(4); s.sendall(pack(request)); response = recv_obj(s)
            if not response or not response.get('ok'): raise OSError('پاسخ دریافت نشد')


class SettingsDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent); self.app = parent
        self.setWindowTitle('تنظیمات LanChat'); self.setMinimumWidth(390)
        layout = QVBoxLayout(self); form = QFormLayout()
        self.name = QLineEdit(parent.profile.get('name',''))
        self.theme = QComboBox(); self.theme.addItem('تیره', 'dark'); self.theme.addItem('روشن', 'light')
        self.theme.setCurrentIndex(0 if parent.profile.get('theme','dark') == 'dark' else 1)
        self.save_logs = QCheckBox('ذخیره پیام‌های ارسالی و دریافتی در این رایانه')
        self.save_logs.setChecked(parent.profile.get('save_messages', True))
        self.notifications = QCheckBox('نمایش اعلان پیام جدید'); self.notifications.setChecked(parent.profile.get('notifications', True))
        form.addRow('نام نمایشی:', self.name); form.addRow('پوسته:', self.theme)
        layout.addLayout(form); layout.addWidget(self.save_logs); layout.addWidget(self.notifications)
        buttons = QHBoxLayout(); save = QPushButton('ذخیره'); cancel = QPushButton('انصراف')
        save.clicked.connect(self.accept); cancel.clicked.connect(self.reject); buttons.addWidget(save); buttons.addWidget(cancel)
        layout.addLayout(buttons)

    def values(self):
        return {'name': self.name.text().strip() or socket.gethostname(), 'theme':self.theme.currentData(),
                'save_messages':self.save_logs.isChecked(), 'notifications':self.notifications.isChecked()}


class LanChat(QMainWindow):
    def __init__(self):
        super().__init__(); self.profile = load_profile(); save_profile(self.profile)
        self.selected_peer = None; self.chat_history = {}
        self.events = Events(); self.events.peers_changed.connect(self.refresh_peers)
        self.events.message_received.connect(self.receive_message); self.events.status.connect(self.set_status)
        self.network = PeerNetwork(self.profile, self.events)
        self.setWindowTitle(f'LanChat {APP_VERSION}'); self.resize(900, 590)
        self._build_ui(); self._setup_tray(); self.apply_theme(); self.network.start()
        self.timer = QTimer(self); self.timer.timeout.connect(self.refresh_peers); self.timer.start(2500)

    def _build_ui(self):
        root = QWidget(); self.setCentralWidget(root); main = QVBoxLayout(root)
        top = QHBoxLayout(); title = QLabel('LanChat'); title.setStyleSheet('font-size:22px;font-weight:700;')
        self.status = QLabel('در حال جست‌وجوی کاربران شبکه…'); settings = QPushButton('تنظیمات'); about = QPushButton('درباره برنامه')
        settings.clicked.connect(self.open_settings); about.clicked.connect(self.about)
        top.addWidget(title); top.addStretch(); top.addWidget(self.status); top.addWidget(settings); top.addWidget(about); main.addLayout(top)
        body = QHBoxLayout(); main.addLayout(body, 1)
        left = QVBoxLayout(); left.addWidget(QLabel('کاربران آنلاین (کشف خودکار)'))
        self.users = QListWidget(); self.users.currentItemChanged.connect(self.select_peer); left.addWidget(self.users)
        self.refresh_btn = QPushButton('به‌روزرسانی فهرست'); self.refresh_btn.clicked.connect(self.refresh_peers); left.addWidget(self.refresh_btn)
        body.addLayout(left, 1)
        right = QVBoxLayout(); self.chat_title = QLabel('برای شروع، یک کاربر آنلاین انتخاب کن')
        self.chat = QTextEdit(); self.chat.setReadOnly(True); self.chat.setPlaceholderText('پیام‌های این گفت‌وگو در همین رایانه ذخیره می‌شوند.')
        compose = QHBoxLayout(); self.entry = QLineEdit(); self.entry.setPlaceholderText('پیام بنویس…'); self.entry.returnPressed.connect(self.send_text)
        send = QPushButton('ارسال'); send.clicked.connect(self.send_text); compose.addWidget(self.entry, 1); compose.addWidget(send)
        right.addWidget(self.chat_title); right.addWidget(self.chat, 1); right.addLayout(compose); body.addLayout(right, 3)
        self.set_status('کشف خودکار فعال است؛ کاربران باید LanChat را باز داشته باشند.')

    def _setup_tray(self):
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(self.windowIcon() if not self.windowIcon().isNull() else self.style().standardIcon(QStyle.SP_ComputerIcon))
        menu = QMenu(); show = menu.addAction('نمایش LanChat'); show.triggered.connect(self.showNormal)
        quit_action = menu.addAction('خروج'); quit_action.triggered.connect(self.quit_app)
        self.tray.setContextMenu(menu); self.tray.activated.connect(lambda reason: self.showNormal() if reason == QSystemTrayIcon.ActivationReason.Trigger else None)
        if QSystemTrayIcon.isSystemTrayAvailable(): self.tray.show()

    def apply_theme(self):
        if self.profile.get('theme') == 'light':
            self.setStyleSheet('QMainWindow,QWidget{background:#f3f5f7;color:#17202a} QPushButton{background:#dce6f1;color:#17202a;padding:7px;border-radius:5px} QListWidget,QTextEdit,QLineEdit{background:white;color:#17202a;border:1px solid #aab7c4;padding:5px}')
        else:
            self.setStyleSheet('QMainWindow,QWidget{background:#20252b;color:#edf2f7} QPushButton{background:#354b60;color:white;padding:7px;border-radius:5px} QListWidget,QTextEdit,QLineEdit{background:#15191e;color:#edf2f7;border:1px solid #485461;padding:5px} QListWidget::item:selected{background:#236b8e}')

    def set_status(self, text): self.status.setText(text)

    def refresh_peers(self):
        peers = sorted(self.network.get_peers(), key=lambda p:p['name'].casefold())
        selected_id = self.selected_peer['id'] if self.selected_peer else None
        self.users.blockSignals(True); self.users.clear(); selected_item = None
        for p in peers:
            item = QListWidgetItem(f"🟢  {p['name']}   ({p['ip']})"); item.setData(Qt.ItemDataRole.UserRole, p); self.users.addItem(item)
            if p['id'] == selected_id: selected_item = item
        if selected_item: self.users.setCurrentItem(selected_item)
        self.users.blockSignals(False)
        if not peers: self.set_status('هنوز کاربری پیدا نشده؛ شبکه و فایروال ویندوز را بررسی کن.')
        else: self.set_status(f'{len(peers)} کاربر آنلاین')

    def select_peer(self, current, previous=None):
        if not current: return
        self.selected_peer = current.data(Qt.ItemDataRole.UserRole)
        self.chat_title.setText(f"گفت‌وگو با {self.selected_peer['name']} ({self.selected_peer['ip']})")
        self.chat.setPlainText(self.chat_history.get(self.selected_peer['id'], ''))

    def append_chat(self, peer_id, line):
        self.chat_history[peer_id] = self.chat_history.get(peer_id, '') + line + '\n'
        if self.selected_peer and self.selected_peer['id'] == peer_id: self.chat.append(line)

    def send_text(self):
        if not self.selected_peer:
            QMessageBox.information(self, 'انتخاب کاربر', 'ابتدا یک کاربر آنلاین از فهرست انتخاب کن.'); return
        text = self.entry.text().strip()
        if not text: return
        peer = dict(self.selected_peer)
        try:
            self.network.send_message(peer, text)
            stamp = datetime.now().strftime('%H:%M:%S')
            line = f'[{stamp}] من: {text}'; self.append_chat(peer['id'], line)
            if self.profile.get('save_messages', True): save_message(f"به {peer['name']} ({peer['ip']}): {text}")
            self.entry.clear()
        except OSError as e:
            QMessageBox.warning(self, 'ارسال ناموفق', f'پیام ارسال نشد. بررسی کن کاربر هنوز آنلاین باشد و فایروال اجازه ارتباط بدهد.\n\nجزئیات: {e}')
            self.refresh_peers()

    def receive_message(self, msg):
        peer_id = msg['from']; stamp = msg.get('time','')
        try: stamp = datetime.fromisoformat(stamp).strftime('%H:%M:%S')
        except Exception: stamp = datetime.now().strftime('%H:%M:%S')
        self.append_chat(peer_id, f"[{stamp}] {msg['name']}: {msg['text']}")
        if self.profile.get('save_messages', True): save_message(f"از {msg['name']} ({msg['ip']}): {msg['text']}")
        if self.profile.get('notifications', True) and (not self.isVisible() or not self.isActiveWindow()):
            self.tray.showMessage('پیام جدید در LanChat', f"{msg['name']}: {msg['text'][:180]}", QSystemTrayIcon.MessageIcon.Information, 4000)
        self.refresh_peers()

    def open_settings(self):
        dlg = SettingsDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.profile.update(dlg.values()); save_profile(self.profile); self.apply_theme()
            self.setWindowTitle(f"LanChat {APP_VERSION} — {self.profile['name']}")

    def about(self):
        QMessageBox.about(self, 'درباره LanChat', f'<h3>LanChat {APP_VERSION}</h3><p>پیام‌رسان مستقیم در شبکه محلی، بدون مدیر یا سرور مرکزی.</p><p>توسعه‌دهنده: حامد محمدی</p><p>ایمیل: <a href="mailto:{DEVELOPER_EMAIL}">{DEVELOPER_EMAIL}</a></p><p>پیام‌ها فقط در رایانه‌های فرستنده و گیرنده ذخیره می‌شوند (در صورت فعال بودن ذخیره پیام).</p>')

    def closeEvent(self, event):
        if self.profile.get('close_to_tray', False) and self.tray.isVisible():
            self.hide(); event.ignore()
        else:
            self.network.stop(); event.accept()

    def quit_app(self):
        self.network.stop(); self.tray.hide(); QApplication.quit()


def main():
    app = QApplication(sys.argv); app.setApplicationName(APP_NAME)
    try:
        icon = Path(getattr(sys, '_MEIPASS', Path(__file__).parent)) / 'lanchat.ico'
        if icon.exists(): app.setWindowIcon(QIcon(str(icon)))
    except Exception: pass
    window = LanChat(); window.show(); sys.exit(app.exec())

if __name__ == '__main__': main()
