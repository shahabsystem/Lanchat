import sys, os, json, socket, threading, time, uuid, struct, logging, platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime
from PySide6.QtCore import Qt, Signal, QObject, QTimer
from PySide6.QtGui import QIcon, QDesktopServices, QFont
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QListWidget, QListWidgetItem, QTextEdit, QLineEdit, QPushButton, QMessageBox,
    QSystemTrayIcon, QMenu, QStyle, QDialog, QFormLayout, QCheckBox, QComboBox, QFontComboBox, QSpinBox, QInputDialog)

APP_NAME = 'LanChat'
APP_VERSION = '1.4.0'
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
    p.setdefault('notification_sound', True)
    p.setdefault('always_on_top', False)
    p.setdefault('font_family', 'Segoe UI')
    p.setdefault('font_size', 10)
    p.setdefault('peer_groups', {})
    p.setdefault('groups', ['عمومی'])
    p.setdefault('close_to_tray', True)
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
        self.sound = QCheckBox('پخش صدای اعلان'); self.sound.setChecked(parent.profile.get('notification_sound', True))
        self.topmost = QCheckBox('قرار گرفتن پنجره روی همه برنامه‌ها'); self.topmost.setChecked(parent.profile.get('always_on_top', False))
        self.font = QFontComboBox(); self.font.setCurrentFont(QFont(parent.profile.get('font_family', 'Segoe UI')))
        self.font_size = QSpinBox(); self.font_size.setRange(8, 28); self.font_size.setValue(int(parent.profile.get('font_size', 10)))
        form.addRow('نام نمایشی:', self.name); form.addRow('پوسته:', self.theme); form.addRow('فونت:', self.font); form.addRow('اندازه فونت:', self.font_size)
        layout.addLayout(form); layout.addWidget(self.save_logs); layout.addWidget(self.notifications); layout.addWidget(self.sound); layout.addWidget(self.topmost)
        buttons = QHBoxLayout(); save = QPushButton('ذخیره'); cancel = QPushButton('انصراف')
        save.clicked.connect(self.accept); cancel.clicked.connect(self.reject); buttons.addWidget(save); buttons.addWidget(cancel)
        layout.addLayout(buttons)

    def values(self):
        return {'name': self.name.text().strip() or socket.gethostname(), 'theme':self.theme.currentData(),
                'save_messages':self.save_logs.isChecked(), 'notifications':self.notifications.isChecked(), 'notification_sound':self.sound.isChecked(),
                'always_on_top':self.topmost.isChecked(), 'font_family':self.font.currentFont().family(), 'font_size':self.font_size.value()}


class LanChat(QMainWindow):
    def __init__(self):
        super().__init__(); self.profile = load_profile(); save_profile(self.profile)
        self.selected_peer = None; self.chat_history = {}
        self.events = Events(); self.events.peers_changed.connect(self.refresh_peers)
        self.events.message_received.connect(self.receive_message); self.events.status.connect(self.set_status)
        self.network = PeerNetwork(self.profile, self.events)
        self.setWindowTitle(f'LanChat {APP_VERSION}'); self.resize(900, 590)
        self._build_ui(); self._setup_tray(); self._setup_notification_popup(); self.apply_theme(); self.apply_window_flags(); self.network.start()
        self.timer = QTimer(self); self.timer.timeout.connect(self.refresh_peers); self.timer.start(2500)

    def _build_ui(self):
        root = QWidget(); self.setCentralWidget(root); main = QVBoxLayout(root)
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
        self.group_send_btn = QPushButton('ارسال پیام به گروه انتخاب‌شده'); self.group_send_btn.clicked.connect(self.send_to_group); left.addWidget(self.group_send_btn)
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
        self.toast.setStyleSheet('#LanChatToast{background:#17283b;color:#ffffff;border:1px solid #2196f3;border-radius:10px;} QLabel{background:transparent;color:#ffffff;}')
        self.toast_timer = QTimer(self); self.toast_timer.setSingleShot(True); self.toast_timer.timeout.connect(self.toast.hide)

    def restore_window(self):
        self.showNormal(); self.raise_(); self.activateWindow()

    def show_notification(self, sender, text):
        if not self.profile.get('notifications', True):
            return
        title = f'پیام جدید از {sender}'
        body = str(text)[:220]
        # Prefer native Windows notification through Qt tray; use a visible fallback popup too.
        try:
            if QSystemTrayIcon.isSystemTrayAvailable() and self.tray.isVisible():
                self.tray.showMessage(title, body, QSystemTrayIcon.MessageIcon.Information, 8000)
        except Exception:
            pass
        try:
            self.toast_title.setText(title)
            self.toast_text.setText(body)
            screen = QApplication.primaryScreen()
            if screen:
                area = screen.availableGeometry()
                self.toast.adjustSize()
                self.toast.move(area.right() - self.toast.width() - 18, area.top() + 18)
            self.toast.show(); self.toast.raise_()
            self.toast_timer.start(8000)
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
        # Keep the selected font consistent across the whole interface.
        font = QFont(str(self.profile.get('font_family', 'Segoe UI')), int(self.profile.get('font_size', 10)))
        QApplication.instance().setFont(font)
        if self.profile.get('theme') == 'light':
            self.setStyleSheet('QMainWindow,QWidget{background:#f3f5f7;color:#17202a} QPushButton{background:#dce6f1;color:#17202a;padding:7px;border-radius:5px} QListWidget,QTextEdit,QLineEdit,QComboBox{background:white;color:#17202a;border:1px solid #aab7c4;padding:5px}')
        else:
            self.setStyleSheet('QMainWindow,QWidget{background:#20252b;color:#edf2f7} QPushButton{background:#354b60;color:white;padding:7px;border-radius:5px} QListWidget,QTextEdit,QLineEdit,QComboBox{background:#15191e;color:#edf2f7;border:1px solid #485461;padding:5px} QListWidget::item:selected{background:#236b8e}')

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
            item = QListWidgetItem(f"🟢  {p['name']}   ({p['ip']})"); item.setData(Qt.ItemDataRole.UserRole, p); self.users.addItem(item)
            if p['id'] == selected_id: selected_item = item
        if selected_item: self.users.setCurrentItem(selected_item)
        self.users.blockSignals(False)
        if not peers: self.set_status('هنوز کاربری پیدا نشده؛ شبکه و فایروال ویندوز را بررسی کن.')
        else: self.set_status(f'{len(peers)} کاربر آنلاین')

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

    def _send_async(self, peers, text, label):
        if not peers or not text.strip(): return
        self.entry.clear()
        self.set_status(f'در حال ارسال به {len(peers)} کاربر…')
        def worker():
            errors = []; ok_count = 0
            def send_one(peer):
                self.network.send_message(peer, text)
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
        text = self.entry.text().strip()
        if not text: QMessageBox.information(self, 'پیام همگانی', 'ابتدا متن پیام را بنویس.'); return
        peers = self.network.get_peers()
        if not peers: QMessageBox.information(self, 'پیام همگانی', 'کاربر آنلاینی پیدا نشده است.'); return
        self._send_async(peers, text, 'همگانی')

    def send_to_group(self):
        group = self.group_filter.currentData()
        if not group or group == '__all__':
            QMessageBox.information(self, 'ارسال گروهی', 'ابتدا یک گروه مشخص را از فهرست گروه‌ها انتخاب کن.'); return
        text = self.entry.text().strip()
        if not text: QMessageBox.information(self, 'ارسال گروهی', 'ابتدا متن پیام را بنویس.'); return
        peers = [p for p in self.network.get_peers() if self.profile.get('peer_groups', {}).get(p['id'], 'عمومی') == group]
        if not peers: QMessageBox.information(self, 'ارسال گروهی', 'در این گروه کاربر آنلاینی وجود ندارد.'); return
        self._send_async(peers, text, f'گروه {group}')

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
        if not self.isActiveWindow():
            self.show_notification(msg['name'], msg['text'])
        self.refresh_peers()

    def open_settings(self):
        dlg = SettingsDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.profile.update(dlg.values()); save_profile(self.profile); self.apply_theme(); self.apply_window_flags()
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
