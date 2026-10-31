import sys, os, json, socket, threading, time, uuid, struct, logging, platform, hashlib, shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime
from PySide6.QtCore import Qt, Signal, QObject, QTimer
from PySide6.QtGui import QIcon, QDesktopServices, QFont
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QListWidget, QListWidgetItem, QTextEdit, QLineEdit, QPushButton, QMessageBox,
    QSystemTrayIcon, QMenu, QStyle, QDialog, QFormLayout, QCheckBox, QComboBox, QFontComboBox, QSpinBox, QInputDialog, QColorDialog)

APP_NAME = 'LanChat'
APP_VERSION = '1.7.0'
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
    p.setdefault('theme', 'terminal')
    p.setdefault('save_messages', True)
    p.setdefault('notifications', True)
    p.setdefault('notification_sound', True)
    p.setdefault('always_on_top', False)
    p.setdefault('font_family', 'Tahoma')
    p.setdefault('font_size', 10)
    p.setdefault('peer_groups', {})
    p.setdefault('groups', ['عمومی'])
    p.setdefault('close_to_tray', True)
    p.setdefault('start_with_windows', False)
    p.setdefault('notification_duration', 20)
    p.setdefault('ui_bg_color', '#0C0C0C')
    p.setdefault('ui_text_color', '#CCCCCC')
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
    pause_changed = Signal(float, str)


class PeerNetwork:
    """Decentralized LAN peer: each running client advertises and accepts direct messages."""
    def __init__(self, profile, events):
        self.profile, self.events = profile, events
        self.lock = threading.RLock()
        self.peers = {}  # stable peer id -> {name, ip, last_seen}
        self.running = False
        self.udp = None
        self.tcp = None
        self.send_paused_until = 0.0
        self.pause_reason = ''

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
            conn.settimeout(60)
            try:
                obj = recv_obj(conn)
                if not isinstance(obj, dict): return
                if obj.get('kind') == 'update_request':
                    if not getattr(sys, 'frozen', False):
                        conn.sendall(pack({'ok': False, 'error': 'نسخهٔ اجرایی برای توزیع موجود نیست'})); return
                    exe_path = Path(sys.executable)
                    size = exe_path.stat().st_size
                    if size > 150 * 1024 * 1024:
                        conn.sendall(pack({'ok': False, 'error': 'حجم فایل به‌روزرسانی بیش از حد مجاز است'})); return
                    digest = hashlib.sha256(exe_path.read_bytes()).hexdigest()
                    conn.sendall(pack({'ok': True, 'version': APP_VERSION, 'size': size, 'sha256': digest}))
                    with exe_path.open('rb') as src:
                        while True:
                            chunk = src.read(1024 * 1024)
                            if not chunk: break
                            conn.sendall(chunk)
                elif obj.get('kind') == 'pause_sending':
                    seconds = max(0, min(120, int(obj.get('seconds', 0))))
                    if seconds:
                        self.send_paused_until = max(self.send_paused_until, time.monotonic() + seconds)
                        self.pause_reason = str(obj.get('name', 'یکی از کاربران'))[:64]
                        self.events.pause_changed.emit(self.send_paused_until, self.pause_reason)
                    conn.sendall(pack({'ok': True}))
                elif obj.get('kind') == 'message' and obj.get('to') == self.profile['id']:
                    sender = str(obj.get('from', ''))
                    if not sender or sender == self.profile['id']: return
                    if time.monotonic() < self.send_paused_until:
                        conn.sendall(pack({'ok': False, 'error': 'ارسال پیام در شبکه موقتاً متوقف شده است'})); return
                    message = {'kind':'message', 'from':sender,
                        'name':str(obj.get('name','کاربر'))[:64], 'text':str(obj.get('text',''))[:12000],
                        'category':str(obj.get('category','direct'))[:24], 'time':str(obj.get('time','')), 'ip':addr[0]}
                    self._update_peer(sender, message['name'], addr[0], str(obj.get('version', 'نامشخص'))[:20])
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
                self._update_peer(peer_id, name, ip, str(obj.get('version', 'نامشخص'))[:20])
                # Unicast reply helps peers on networks where broadcast delivery is asymmetric.
                try:
                    reply = self._beacon_data()
                    s.sendto(json.dumps(reply, ensure_ascii=False).encode('utf-8'), addr)
                except OSError: pass
        except OSError as e:
            self.events.status.emit(f'کشف خودکار شبکه در دسترس نیست: {e}')

    def _beacon_data(self):
        return {'kind':BEACON, 'id':self.profile['id'], 'name':str(self.profile.get('name') or socket.gethostname())[:64], 'port':TCP_PORT, 'version':APP_VERSION, 'time':time.time()}

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

    def _update_peer(self, peer_id, name, ip, version='نامشخص'):
        changed = False
        with self.lock:
            old = self.peers.get(peer_id)
            if not old or old.get('name') != name or old.get('ip') != ip or old.get('version') != version: changed = True
            self.peers[peer_id] = {'id':peer_id, 'name':name, 'ip':ip, 'version':version, 'last_seen':time.monotonic()}
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

    def send_message(self, peer, text, category='direct'):
        request = {'kind':'message', 'from':self.profile['id'], 'to':peer['id'],
                   'name':str(self.profile.get('name') or socket.gethostname())[:64], 'version':APP_VERSION,
                   'category':category, 'text':text, 'time':datetime.now().isoformat(timespec='seconds')}
        with socket.create_connection((peer['ip'], TCP_PORT), timeout=3) as s:
            s.settimeout(4); s.sendall(pack(request)); response = recv_obj(s)
            if not response or not response.get('ok'): raise OSError((response or {}).get('error', 'پاسخ دریافت نشد'))


class SettingsDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent); self.app = parent
        self.setWindowTitle('تنظیمات LanChat'); self.setMinimumWidth(390)
        layout = QVBoxLayout(self); form = QFormLayout()
        self.name = QLineEdit(parent.profile.get('name',''))
        self.theme = QComboBox(); self.theme.addItem('Command Prompt (سیاه ترمینال)', 'terminal'); self.theme.addItem('تیره', 'dark'); self.theme.addItem('روشن', 'light')
        self.theme.setCurrentIndex(max(0, self.theme.findData(parent.profile.get('theme', 'terminal'))))
        self.save_logs = QCheckBox('ذخیره پیام‌های ارسالی و دریافتی در این رایانه')
        self.save_logs.setChecked(parent.profile.get('save_messages', True))
        self.notifications = QCheckBox('نمایش اعلان پیام جدید'); self.notifications.setChecked(parent.profile.get('notifications', True))
        self.sound = QCheckBox('پخش صدای اعلان'); self.sound.setChecked(parent.profile.get('notification_sound', True))
        self.topmost = QCheckBox('قرار گرفتن پنجره روی همه برنامه‌ها'); self.topmost.setChecked(parent.profile.get('always_on_top', False))
        self.startup = QCheckBox('اجرای خودکار پس از ورود به ویندوز'); self.startup.setChecked(parent.profile.get('start_with_windows', False))
        self.toast_duration = QSpinBox(); self.toast_duration.setRange(5, 120); self.toast_duration.setSuffix(' ثانیه'); self.toast_duration.setValue(int(parent.profile.get('notification_duration', 20)))
        self.bg_color = parent.profile.get('ui_bg_color', '#0C0C0C')
        self.text_color = parent.profile.get('ui_text_color', '#CCCCCC')
        self.bg_button = QPushButton(self.bg_color); self.text_button = QPushButton(self.text_color)
        self.bg_button.clicked.connect(lambda: self.pick_color('bg')); self.text_button.clicked.connect(lambda: self.pick_color('text'))
        self.font = QFontComboBox(); self.font.setCurrentFont(QFont(parent.profile.get('font_family', 'Tahoma')))
        if not parent.profile.get('font_family'): self.font.setCurrentFont(QFont('Tahoma'))
        self.font_size = QSpinBox(); self.font_size.setRange(8, 28); self.font_size.setValue(int(parent.profile.get('font_size', 10)))
        form.addRow('نام نمایشی:', self.name); form.addRow('پوسته:', self.theme); form.addRow('فونت:', self.font); form.addRow('اندازه فونت:', self.font_size)
        form.addRow('مدت نمایش اعلان:', self.toast_duration)
        form.addRow('رنگ پس‌زمینه پنجره:', self.bg_button); form.addRow('رنگ نوشته‌ها:', self.text_button)
        layout.addLayout(form); layout.addWidget(self.save_logs); layout.addWidget(self.notifications); layout.addWidget(self.sound); layout.addWidget(self.topmost); layout.addWidget(self.startup)
        buttons = QHBoxLayout(); save = QPushButton('ذخیره'); cancel = QPushButton('انصراف')
        save.clicked.connect(self.accept); cancel.clicked.connect(self.reject); buttons.addWidget(save); buttons.addWidget(cancel)
        layout.addLayout(buttons)

    def pick_color(self, which):
        current = self.bg_color if which == 'bg' else self.text_color
        color = QColorDialog.getColor(__import__('PySide6.QtGui', fromlist=['QColor']).QColor(current), self, 'انتخاب رنگ')
        if color.isValid():
            if which == 'bg': self.bg_color = color.name(); self.bg_button.setText(self.bg_color)
            else: self.text_color = color.name(); self.text_button.setText(self.text_color)

    def values(self):
        return {'ui_bg_color':self.bg_color, 'ui_text_color':self.text_color, 'name': self.name.text().strip() or socket.gethostname(), 'theme':self.theme.currentData(),
                'save_messages':self.save_logs.isChecked(), 'notifications':self.notifications.isChecked(), 'notification_sound':self.sound.isChecked(),
                'always_on_top':self.topmost.isChecked(), 'start_with_windows':self.startup.isChecked(), 'notification_duration':self.toast_duration.value(), 'font_family':self.font.currentFont().family(), 'font_size':self.font_size.value()}


class LanChat(QMainWindow):
    def __init__(self):
        super().__init__(); self.profile = load_profile(); save_profile(self.profile)
        self.selected_peer = None; self.chat_history = {}
        self.events = Events(); self.events.peers_changed.connect(self.refresh_peers)
        self.events.message_received.connect(self.receive_message); self.events.status.connect(self.set_status)
        self.events.pause_changed.connect(self.on_pause_changed)
        self.network = PeerNetwork(self.profile, self.events)
        self.setWindowTitle(f'LanChat {APP_VERSION}'); self.resize(900, 590)
        self._build_ui(); self._setup_tray(); self._setup_notification_popup(); self.apply_theme(); self.apply_window_flags(); self.network.start()
        self.timer = QTimer(self); self.timer.timeout.connect(self.refresh_peers); self.timer.start(2500)
        self.pause_timer = QTimer(self); self.pause_timer.timeout.connect(self.update_pause_ui); self.pause_timer.start(500)
        self.update_downloads = set()
        self.apply_startup_setting()

    def _build_ui(self):
        root = QWidget(); root.setObjectName('centralWidget'); self.setCentralWidget(root); main = QVBoxLayout(root)
        top = QHBoxLayout(); title = QLabel('LanChat'); title.setStyleSheet('font-size:22px;font-weight:700;')
        self.status = QLabel('در حال جست‌وجوی کاربران شبکه…'); settings = QPushButton('تنظیمات'); about = QPushButton('درباره برنامه')
        settings.clicked.connect(self.open_settings); about.clicked.connect(self.about)
        top.addWidget(title); top.addStretch(); top.addWidget(self.status); top.addWidget(settings); top.addWidget(about); main.addLayout(top)
        body = QHBoxLayout(); main.addLayout(body, 1)
        left = QVBoxLayout(); left.addWidget(QLabel('کاربران آنلاین (کشف خودکار)'))
        group_row = QHBoxLayout(); self.group_filter = QComboBox(); self.group_filter.addItem('همه کاربران', '__all__'); self.group_filter.currentIndexChanged.connect(self.refresh_peers); group_row.addWidget(self.group_filter, 1)
        add_group = QPushButton('گروه جدید'); add_group.clicked.connect(self.create_group); group_row.addWidget(add_group)
        assign_group = QPushButton('گروه‌بندی کاربر'); assign_group.clicked.connect(self.assign_group); group_row.addWidget(assign_group); left.addLayout(group_row)
        self.users = QListWidget(); self.users.currentItemChanged.connect(self.select_peer); left.addWidget(self.users)
        self.refresh_btn = QPushButton('به‌روزرسانی فهرست'); self.refresh_btn.clicked.connect(self.refresh_peers); left.addWidget(self.refresh_btn)
        self.broadcast_btn = QPushButton('ارسال پیام به همه کاربران'); self.broadcast_btn.clicked.connect(self.send_to_all); left.addWidget(self.broadcast_btn)
        self.pause_btn = QPushButton('توقف موقت ارسال پیام در شبکه'); self.pause_btn.clicked.connect(self.pause_network_sending); left.addWidget(self.pause_btn)
        self.pause_after_group = QCheckBox('پس از ارسال گروهی، ارسال همه کاربران متوقف شود')
        self.group_pause_duration = QComboBox(); self.group_pause_duration.addItem('۶۰ ثانیه', 60); self.group_pause_duration.addItem('۱۲۰ ثانیه', 120)
        pause_row = QHBoxLayout(); pause_row.addWidget(self.pause_after_group); pause_row.addWidget(self.group_pause_duration); left.addLayout(pause_row)
        self.group_send_btn = QPushButton('ارسال پیام به گروه انتخاب‌شده'); self.group_send_btn.clicked.connect(self.send_to_group); left.addWidget(self.group_send_btn)
        body.addLayout(left, 1)
        right = QVBoxLayout(); self.chat_title = QLabel('برای شروع، یک کاربر آنلاین انتخاب کن')
        self.chat = QTextEdit(); self.chat.setReadOnly(True); self.chat.setPlaceholderText('پیام‌های این گفت‌وگو در همین رایانه ذخیره می‌شوند.')
        compose = QHBoxLayout(); self.entry = QLineEdit(); self.entry.setPlaceholderText('پیام بنویس…'); self.entry.returnPressed.connect(self.send_text)
        send = QPushButton('ارسال'); send.clicked.connect(self.send_text); self.send_button = send; compose.addWidget(self.entry, 1); compose.addWidget(send)
        right.addWidget(self.chat_title); right.addWidget(self.chat, 1); right.addLayout(compose); body.addLayout(right, 3)
        self.set_status('کشف خودکار فعال است؛ کاربران باید LanChat را باز داشته باشند.')

    def _setup_tray(self):
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(self.windowIcon() if not self.windowIcon().isNull() else self.style().standardIcon(QStyle.SP_ComputerIcon))
        menu = QMenu(); show = menu.addAction('نمایش LanChat'); show.triggered.connect(self.restore_window)
        menu.addSeparator()
        quit_action = menu.addAction('خروج کامل'); quit_action.triggered.connect(self.quit_app)
        self.tray.setContextMenu(menu); self.tray.activated.connect(lambda reason: self.restore_window() if reason == QSystemTrayIcon.ActivationReason.Trigger else None)
        if QSystemTrayIcon.isSystemTrayAvailable(): self.tray.show()

    def _setup_notification_popup(self):
        # A native tray balloon is not guaranteed to appear on every Windows setup.
        # This lightweight in-app toast is a fallback, independent of Windows toast settings.
        self.toast = QWidget(None, Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.toast.setObjectName('LanChatToast')
        self.toast.setFixedWidth(340)
        toast_layout = QVBoxLayout(self.toast)
        toast_layout.setContentsMargins(14, 10, 14, 12)
        self.toast_title = QLabel('پیام جدید در LanChat')
        self.toast_title.setStyleSheet('font-weight:700;font-size:14px;')
        self.toast_text = QLabel('')
        self.toast_text.setWordWrap(True)
        toast_layout.addWidget(self.toast_title)
        toast_layout.addWidget(self.toast_text)
        self.toast.setStyleSheet('#LanChatToast{background:#0C0C0C;color:#CCCCCC;border:1px solid #666666;border-radius:2px;} QLabel{background:transparent;color:#CCCCCC;}')
        self.toast_timer = QTimer(self); self.toast_timer.setSingleShot(True); self.toast_timer.timeout.connect(self.toast.hide)

    def restore_window(self):
        self.showNormal(); self.raise_(); self.activateWindow()

    def show_notification(self, sender, text, category='direct'):
        if not self.profile.get('notifications', True):
            return
        is_group = category in ('group', 'broadcast')
        prefix = 'پیام همگانی' if category == 'broadcast' else ('پیام گروهی' if category == 'group' else 'پیام جدید')
        title = f'{prefix} از {sender}'
        body = str(text)[:1200]
        # Use our own topmost popup as the primary, readable notification; Windows tray balloons are optional.
        try:
            self.toast_title.setText(title)
            previous = self.toast_text.text().strip()
            combined = (previous + ('\n\n' if previous else '') + f'{sender}: {body}')
            self.toast_text.setText(combined[-6000:])
            self.toast.adjustSize()
            screen = QApplication.primaryScreen()
            if screen:
                area = screen.availableGeometry()
                self.toast.move(area.right() - self.toast.width() - 18, area.bottom() - self.toast.height() - 36)
            self.toast.show(); self.toast.raise_()
            self.toast_timer.start(int(self.profile.get('notification_duration', 20)) * 1000)
        except Exception:
            logging.exception('Could not show in-app notification popup')
        try:
            if QSystemTrayIcon.isSystemTrayAvailable() and self.tray.isVisible():
                self.tray.showMessage(title, body[:240], QSystemTrayIcon.MessageIcon.Information, int(self.profile.get('notification_duration', 20)) * 1000)
        except Exception:
            pass
        if self.profile.get('notification_sound', True) and platform.system() == 'Windows':
            try:
                import winsound
                winsound.MessageBeep(winsound.MB_ICONASTERISK)
            except Exception:
                try: QApplication.beep()
                except Exception: pass

    def apply_window_flags(self):
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, bool(self.profile.get('always_on_top', False)))
        if self.isVisible(): self.show()

    def apply_theme(self):
        # Terminal-inspired palette, with Tahoma for reliable Persian glyph coverage.
        font = QFont(str(self.profile.get('font_family', 'Tahoma')), int(self.profile.get('font_size', 10)))
        QApplication.instance().setFont(font)
        theme = self.profile.get('theme', 'terminal')
        if theme == 'light':
            style = '''
                QWidget { background:#F3F5F7; color:#17202A; }
                QMainWindow { background:#F3F5F7; }
                QPushButton { background:#DCE6F1; color:#17202A; border:1px solid #AAB7C4; padding:7px 10px; }
                QPushButton:hover { background:#C8D8E8; }
                QListWidget,QTextEdit,QLineEdit,QComboBox { background:#FFFFFF; color:#17202A; border:1px solid #AAB7C4; padding:5px; selection-background-color:#316AC5; selection-color:#FFFFFF; }
                QMenu { background:#FFFFFF; color:#17202A; border:1px solid #AAB7C4; }
                QMenu::item:selected { background:#316AC5; color:#FFFFFF; }
                QCheckBox,QLabel { background:transparent; }
            '''
        elif theme == 'dark':
            style = '''
                QWidget { background:#20252B; color:#EDF2F7; }
                QMainWindow { background:#20252B; }
                QPushButton { background:#354B60; color:#FFFFFF; border:1px solid #485461; padding:7px 10px; }
                QPushButton:hover { background:#42627D; }
                QListWidget,QTextEdit,QLineEdit,QComboBox { background:#15191E; color:#EDF2F7; border:1px solid #485461; padding:5px; selection-background-color:#236B8E; selection-color:#FFFFFF; }
                QMenu { background:#20252B; color:#EDF2F7; border:1px solid #485461; }
                QMenu::item:selected { background:#236B8E; }
                QCheckBox,QLabel { background:transparent; }
            '''
        else:
            # Windows Command Prompt-like: true black canvas, compact flat controls,
            # classic light-gray text and blue selection. Tahoma is intentionally used
            # instead of Consolas so Persian text renders consistently.
            style = '''
                QWidget { background:#0C0C0C; color:#CCCCCC; }
                QMainWindow { background:#0C0C0C; }
                QDialog { background:#0C0C0C; }
                QLabel { background:transparent; color:#CCCCCC; }
                QPushButton { background:#0C0C0C; color:#CCCCCC; border:1px solid #666666; border-radius:0px; padding:6px 9px; }
                QPushButton:hover { background:#1F1F1F; color:#FFFFFF; border:1px solid #AAAAAA; }
                QPushButton:pressed { background:#333333; }
                QListWidget,QTextEdit,QLineEdit,QComboBox { background:#0C0C0C; color:#CCCCCC; border:1px solid #666666; border-radius:0px; padding:5px; selection-background-color:#264F78; selection-color:#FFFFFF; }
                QListWidget::item { padding:3px; }
                QListWidget::item:selected { background:#264F78; color:#FFFFFF; }
                QComboBox QAbstractItemView { background:#0C0C0C; color:#CCCCCC; selection-background-color:#264F78; }
                QCheckBox { background:transparent; color:#CCCCCC; spacing:7px; }
                QCheckBox::indicator { width:13px; height:13px; background:#0C0C0C; border:1px solid #AAAAAA; }
                QCheckBox::indicator:checked { background:#CCCCCC; border:1px solid #CCCCCC; }
                QSpinBox { background:#0C0C0C; color:#CCCCCC; border:1px solid #666666; padding:4px; }
                QMenu { background:#0C0C0C; color:#CCCCCC; border:1px solid #666666; }
                QMenu::item { padding:5px 24px; }
                QMenu::item:selected { background:#264F78; color:#FFFFFF; }
                QScrollBar:vertical { background:#0C0C0C; width:12px; }
                QScrollBar::handle:vertical { background:#555555; min-height:20px; }
                QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical { height:0px; }
            '''
        bg = str(self.profile.get('ui_bg_color', '#0C0C0C'))
        fg = str(self.profile.get('ui_text_color', '#CCCCCC'))
        # Keep controls theme-styled while allowing the user to tune the main window and text colors.
        style += f'\nQMainWindow, QDialog, QWidget#centralWidget {{ background-color: {bg}; }}\nQWidget {{ color: {fg}; }}\n'
        QApplication.instance().setStyleSheet(style)
        if hasattr(self, 'toast'):
            self.toast.setStyleSheet(f'#LanChatToast{{background:{bg};color:{fg};border:1px solid {fg};border-radius:2px;}} QLabel{{background:transparent;color:{fg};}}')

    def set_status(self, text): self.status.setText(text)

    def refresh_peers(self):
        peers = sorted(self.network.get_peers(), key=lambda p:p['name'].casefold())
        current_group = self.group_filter.currentData() if hasattr(self, 'group_filter') else '__all__'
        groups = self.profile.get('groups', ['عمومی'])
        if hasattr(self, 'group_filter'):
            old = self.group_filter.currentData(); self.group_filter.blockSignals(True); self.group_filter.clear(); self.group_filter.addItem('همه کاربران', '__all__')
            for group in groups: self.group_filter.addItem(group, group)
            idx = self.group_filter.findData(old if old is not None else current_group); self.group_filter.setCurrentIndex(max(0, idx)); self.group_filter.blockSignals(False)
            current_group = self.group_filter.currentData()
        if current_group and current_group != '__all__': peers = [p for p in peers if self.profile.get('peer_groups', {}).get(p['id'], 'عمومی') == current_group]
        selected_id = self.selected_peer['id'] if self.selected_peer else None
        self.users.blockSignals(True); self.users.clear(); selected_item = None
        for p in peers:
            item = QListWidgetItem(f"🟢  {p['name']}   ({p['ip']})   |   نسخه {p.get('version', 'نامشخص')}"); item.setData(Qt.ItemDataRole.UserRole, p); self.users.addItem(item)
            if p['id'] == selected_id: selected_item = item
        if selected_item: self.users.setCurrentItem(selected_item)
        self.users.blockSignals(False)
        if not peers: self.set_status('هنوز کاربری پیدا نشده؛ شبکه و فایروال ویندوز را بررسی کن.')
        else:
            self.set_status(f'{len(peers)} کاربر آنلاین')
            self.check_peer_updates(peers)

    def check_peer_updates(self, peers):
        newer = []
        def version_tuple(v):
            try: return tuple(int(x) for x in str(v).split('.')[:3])
            except Exception: return (0,)
        for peer in peers:
            if version_tuple(peer.get('version', '0')) > version_tuple(APP_VERSION):
                key = (peer['id'], peer.get('version'))
                if key not in self.update_downloads:
                    self.update_downloads.add(key); newer.append(peer)
        for peer in newer:
            threading.Thread(target=self.download_peer_update, args=(peer,), daemon=True).start()

    def download_peer_update(self, peer):
        try:
            request = {'kind': 'update_request', 'from': self.profile['id'], 'version': APP_VERSION}
            with socket.create_connection((peer['ip'], TCP_PORT), timeout=5) as sock:
                sock.settimeout(30); sock.sendall(pack(request)); meta = recv_obj(sock)
                if not meta or not meta.get('ok'): raise OSError((meta or {}).get('error', 'بستهٔ به‌روزرسانی در دسترس نیست'))
                size = int(meta.get('size', 0)); expected = str(meta.get('sha256', ''))
                if size <= 0 or size > 150 * 1024 * 1024 or len(expected) != 64: raise OSError('مشخصات بسته معتبر نیست')
                update_dir = DATA_DIR / 'updates'; update_dir.mkdir(parents=True, exist_ok=True)
                target = update_dir / f'LanChat-{meta.get("version", "new")}.exe'
                temp = target.with_suffix('.download')
                digest = hashlib.sha256(); remaining = size
                with temp.open('wb') as out:
                    while remaining:
                        chunk = sock.recv(min(1024 * 1024, remaining))
                        if not chunk: raise OSError('دریافت بسته ناقص ماند')
                        out.write(chunk); digest.update(chunk); remaining -= len(chunk)
                if digest.hexdigest().lower() != expected.lower():
                    temp.unlink(missing_ok=True); raise OSError('بررسی صحت فایل به‌روزرسانی ناموفق بود')
                temp.replace(target)
                self.events.status.emit(f'نسخهٔ جدید {meta.get("version")} دریافت شد: {target} — برای جایگزینی، برنامه را ببند و فایل جدید را اجرا کن.')
        except Exception as exc:
            self.events.status.emit(f'دریافت خودکار به‌روزرسانی از {peer.get("name", "کاربر") } ناموفق بود: {exc}')

    def create_group(self):
        name, ok = QInputDialog.getText(self, 'گروه جدید', 'نام گروه:')
        name = name.strip()
        if ok and name:
            groups = self.profile.setdefault('groups', ['عمومی'])
            if name not in groups: groups.append(name); save_profile(self.profile)
            self.refresh_peers()
            idx = self.group_filter.findData(name)
            if idx >= 0: self.group_filter.setCurrentIndex(idx)

    def assign_group(self):
        if not self.selected_peer:
            QMessageBox.information(self, 'گروه‌بندی', 'ابتدا یک کاربر آنلاین انتخاب کن.'); return
        groups = self.profile.setdefault('groups', ['عمومی'])
        group, ok = QInputDialog.getItem(self, 'گروه‌بندی کاربر', 'انتقال کاربر به گروه:', groups, 0, False)
        if ok and group:
            self.profile.setdefault('peer_groups', {})[self.selected_peer['id']] = group
            save_profile(self.profile); self.refresh_peers()

    def on_pause_changed(self, until, reason):
        self.set_status(f'ارسال پیام تا {max(0, int(until-time.monotonic()))} ثانیه متوقف است (درخواست {reason})')
        self.update_pause_ui()

    def update_pause_ui(self):
        remaining = max(0, int(self.network.send_paused_until - time.monotonic()))
        paused = remaining > 0
        for widget in (self.entry, self.send_button, self.broadcast_btn, self.group_send_btn):
            widget.setEnabled(not paused)
        self.pause_btn.setText(f'ارسال متوقف است ({remaining} ثانیه)' if paused else 'توقف موقت ارسال پیام در شبکه')

    def pause_network_sending(self):
        choice, ok = QInputDialog.getItem(self, 'توقف موقت ارسال', 'مدت توقف برای همه کاربران آنلاین:', ['۶۰ ثانیه', '۱۲۰ ثانیه'], 0, False)
        if not ok: return
        seconds = 60 if choice.startswith('۶۰') else 120
        peers = self.network.get_peers()
        self.network.send_paused_until = max(self.network.send_paused_until, time.monotonic()+seconds)
        self.network.pause_reason = self.profile.get('name', 'کاربر')
        self.update_pause_ui()
        def worker():
            for peer in peers:
                try:
                    request = {'kind':'pause_sending', 'seconds':seconds, 'name':self.profile.get('name','کاربر')}
                    with socket.create_connection((peer['ip'], TCP_PORT), timeout=2) as sock:
                        sock.settimeout(3); sock.sendall(pack(request)); recv_obj(sock)
                except OSError: pass
        threading.Thread(target=worker, daemon=True).start()
        self.set_status(f'درخواست توقف ارسال برای {len(peers)} کاربر آنلاین ارسال شد؛ {seconds} ثانیه')

    def _send_async(self, peers, text, label):
        if not peers or not text.strip(): return
        self.entry.clear()
        self.set_status(f'در حال ارسال به {len(peers)} کاربر…')
        def worker():
            errors = []; ok_count = 0
            def send_one(peer):
                self.network.send_message(peer, text, 'broadcast' if label == 'همگانی' else ('group' if label.startswith('گروه ') else 'direct'))
                if self.profile.get('save_messages', True):
                    save_message(f"به {peer['name']} ({peer['ip']}) [{label}]: {text}")
                return peer['name']
            with ThreadPoolExecutor(max_workers=min(12, len(peers))) as pool:
                futures = {pool.submit(send_one, peer): peer for peer in peers}
                for future in as_completed(futures):
                    try: future.result(); ok_count += 1
                    except OSError as exc: errors.append(f"{futures[future]['name']}: {exc}")
            self.events.status.emit(f'ارسال تمام شد: {ok_count}/{len(peers)} کاربر')
            if errors: self.events.status.emit(f'ارسال به {len(errors)} کاربر ناموفق بود؛ آنلاین بودن و فایروال را بررسی کن.')
        threading.Thread(target=worker, daemon=True).start()

    def send_to_all(self):
        if time.monotonic() < self.network.send_paused_until:
            QMessageBox.information(self, 'ارسال موقتاً متوقف است', 'در این مدت امکان ارسال پیام وجود ندارد.'); return
        text = self.entry.text().strip()
        if not text: QMessageBox.information(self, 'پیام همگانی', 'ابتدا متن پیام را بنویس.'); return
        peers = self.network.get_peers()
        if not peers: QMessageBox.information(self, 'پیام همگانی', 'کاربر آنلاینی پیدا نشده است.'); return
        self._send_async(peers, text, 'همگانی')

    def send_to_group(self):
        if time.monotonic() < self.network.send_paused_until:
            QMessageBox.information(self, 'ارسال موقتاً متوقف است', 'در این مدت امکان ارسال پیام وجود ندارد.'); return
        group = self.group_filter.currentData()
        if not group or group == '__all__':
            QMessageBox.information(self, 'ارسال گروهی', 'ابتدا یک گروه مشخص را از فهرست گروه‌ها انتخاب کن.'); return
        text = self.entry.text().strip()
        if not text: QMessageBox.information(self, 'ارسال گروهی', 'ابتدا متن پیام را بنویس.'); return
        peers = [p for p in self.network.get_peers() if self.profile.get('peer_groups', {}).get(p['id'], 'عمومی') == group]
        if not peers: QMessageBox.information(self, 'ارسال گروهی', 'در این گروه کاربر آنلاینی وجود ندارد.'); return
        self._send_async(peers, text, f'گروه {group}')
        if self.pause_after_group.isChecked():
            seconds = int(self.group_pause_duration.currentData())
            self.network.send_paused_until = max(self.network.send_paused_until, time.monotonic()+seconds)
            self.network.pause_reason = self.profile.get('name', 'کاربر')
            self.update_pause_ui()
            def pause_worker():
                for peer in self.network.get_peers():
                    try:
                        req = {'kind':'pause_sending', 'seconds':seconds, 'name':self.profile.get('name','کاربر')}
                        with socket.create_connection((peer['ip'], TCP_PORT), timeout=2) as sock:
                            sock.settimeout(3); sock.sendall(pack(req)); recv_obj(sock)
                    except OSError: pass
            threading.Thread(target=pause_worker, daemon=True).start()

    def select_peer(self, current, previous=None):
        if not current: return
        self.selected_peer = current.data(Qt.ItemDataRole.UserRole)
        self.chat_title.setText(f"گفت‌وگو با {self.selected_peer['name']} ({self.selected_peer['ip']})")
        self.chat.setPlainText(self.chat_history.get(self.selected_peer['id'], ''))

    def append_chat(self, peer_id, line):
        self.chat_history[peer_id] = self.chat_history.get(peer_id, '') + line + '\n'
        if self.selected_peer and self.selected_peer['id'] == peer_id: self.chat.append(line)

    def send_text(self):
        if time.monotonic() < self.network.send_paused_until:
            QMessageBox.information(self, 'ارسال موقتاً متوقف است', 'در این مدت امکان ارسال پیام وجود ندارد.'); return
        if not self.selected_peer:
            QMessageBox.information(self, 'انتخاب کاربر', 'ابتدا یک کاربر آنلاین از فهرست انتخاب کن.'); return
        text = self.entry.text().strip()
        if not text: return
        peer = dict(self.selected_peer)
        self.entry.clear()
        stamp = datetime.now().strftime('%H:%M:%S')
        line = f'[{stamp}] من: {text}'; self.append_chat(peer['id'], line)
        if self.profile.get('save_messages', True): save_message(f"به {peer['name']} ({peer['ip']}): {text}")
        def worker():
            try: self.network.send_message(peer, text)
            except OSError as e: self.events.status.emit(f'ارسال ناموفق به {peer["name"]}: {e}')
        threading.Thread(target=worker, daemon=True).start()

    def receive_message(self, msg):
        peer_id = msg['from']; stamp = msg.get('time','')
        try: stamp = datetime.fromisoformat(stamp).strftime('%H:%M:%S')
        except Exception: stamp = datetime.now().strftime('%H:%M:%S')
        self.append_chat(peer_id, f"[{stamp}] {msg['name']}: {msg['text']}")
        if self.profile.get('save_messages', True): save_message(f"از {msg['name']} ({msg['ip']}): {msg['text']}")
        category = msg.get('category', 'direct')
        if category in ('group', 'broadcast') or not self.isActiveWindow():
            self.show_notification(msg['name'], msg['text'], category)
        self.refresh_peers()

    def apply_startup_setting(self):
        if platform.system() != 'Windows': return
        try:
            import winreg
            key_path = r'Software\Microsoft\Windows\CurrentVersion\Run'
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                value_name = 'LanChat'
                if self.profile.get('start_with_windows', False):
                    if getattr(sys, 'frozen', False): command = f'"{sys.executable}"'
                    else: command = f'"{sys.executable}" "{Path(__file__).resolve()}"'
                    winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, command)
                else:
                    try: winreg.DeleteValue(key, value_name)
                    except FileNotFoundError: pass
        except Exception as exc:
            self.events.status.emit(f'تنظیم اجرای خودکار ویندوز انجام نشد: {exc}')

    def open_settings(self):
        dlg = SettingsDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.profile.update(dlg.values()); save_profile(self.profile); self.apply_startup_setting(); self.apply_theme(); self.apply_window_flags()
            self.setWindowTitle(f"LanChat {APP_VERSION} — {self.profile['name']}")

    def about(self):
        QMessageBox.about(self, 'درباره LanChat', f'<h3>LanChat {APP_VERSION}</h3><p>پیام‌رسان مستقیم در شبکه محلی، بدون مدیر یا سرور مرکزی.</p><p>توسعه‌دهنده: حامد محمدی</p><p>ایمیل: <a href="mailto:{DEVELOPER_EMAIL}">{DEVELOPER_EMAIL}</a></p><p>پیام‌ها فقط در رایانه‌های فرستنده و گیرنده ذخیره می‌شوند (در صورت فعال بودن ذخیره پیام).</p>')

    def closeEvent(self, event):
        if self.tray.isVisible():
            self.hide(); event.ignore()
            if self.profile.get('notifications', True):
                try: self.tray.showMessage('LanChat فعال است', 'برنامه در کنار ساعت ویندوز اجرا می‌شود.', QSystemTrayIcon.MessageIcon.Information, 2500)
                except Exception: pass
        else:
            self.network.stop(); event.accept()

    def quit_app(self):
        self.network.stop(); self.toast.hide(); self.tray.hide(); QApplication.quit()


def main():
    app = QApplication(sys.argv); app.setApplicationName(APP_NAME); app.setQuitOnLastWindowClosed(False)
    try:
        icon = Path(getattr(sys, '_MEIPASS', Path(__file__).parent)) / 'lanchat.ico'
        if icon.exists(): app.setWindowIcon(QIcon(str(icon)))
    except Exception: pass
    window = LanChat(); window.show(); sys.exit(app.exec())

if __name__ == '__main__': main()
