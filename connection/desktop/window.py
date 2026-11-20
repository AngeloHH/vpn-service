import threading

from PySide6.QtCore import QLocale, QObject, QRunnable, QSettings, Qt, QThreadPool, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (QComboBox, QFrame, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QPushButton,
                               QScrollArea, QStackedWidget, QVBoxLayout, QWidget)

from connection import __version__
from connection.client_cli import address
from connection.desktop.style import sheet
from connection.desktop.texts import LANGUAGES, Texts
from connection.errors import VPNError
from connection.vpn_service import VPNClient


class Signals(QObject):
    done, failed = Signal(object), Signal(object)


class Task(QRunnable):
    # A call to the server off the window's thread; its answer comes back as a signal.
    def __init__(self, function, *arguments):
        super().__init__()
        self.function, self.arguments, self.signals = function, arguments, Signals()

    def run(self):
        try: result = self.function(*self.arguments)
        except Exception as error: self.signals.failed.emit(error)
        else: self.signals.done.emit(result)


def label(text: str = '', name: str = None, wrap: bool = False) -> QLabel:
    widget = QLabel(text)
    if name: widget.setObjectName(name)
    widget.setWordWrap(wrap)
    return widget


def button(text: str, **properties) -> QPushButton:
    widget = QPushButton(text)
    widget.setCursor(Qt.PointingHandCursor)
    for key, value in properties.items(): widget.setProperty(key, value)
    return widget


def frame(name: str, vertical: bool = True, margins=(0, 0, 0, 0), spacing: int = 0):
    widget = QFrame()
    widget.setObjectName(name)
    layout = (QVBoxLayout if vertical else QHBoxLayout)(widget)
    layout.setContentsMargins(*margins)
    layout.setSpacing(spacing)
    return widget, layout


def speed(value: int) -> str:
    # Bytes per second, as the panel shows rates.
    bits = value * 8
    for unit, size in (('Mbps', 1_000_000), ('kbps', 1_000)):
        if bits >= size: return f'{bits / size:.1f} {unit}'
    return f'{bits} bps'


class Window(QMainWindow):
    """The desktop client: the same VPNClient calls as code and the CLI, with the panel's look."""

    def __init__(self, settings: QSettings = None, client_class=VPNClient, pool: QThreadPool = None):
        super().__init__()
        self.settings = settings or QSettings('vpn-service', 'desktop')
        self.client_class, self.pool = client_class, pool or QThreadPool.globalInstance()
        self.client = self.tunnel = self.tunnel_error = None
        self.account, self.networks, self.selected, self.tasks = {}, [], None, set()
        system = QGuiApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark
        self.theme = self.settings.value('theme') or ('dark' if system else 'light')
        self.texts = Texts(self.settings.value('language'), QLocale.system().name())
        self.setMinimumSize(460, 640)
        self.resize(520, 700)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_status)
        self.timer.start(1000)
        self.build()

    # ---------- Structure ----------

    def build(self):
        t = self.texts
        self.setWindowTitle(t('Conectarse a la VPN'))
        root = QWidget()
        root.setObjectName('page')
        layout = QVBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.top_bar())
        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)
        self.toast_box, toast_layout = frame('toast', margins=(14, 9, 14, 9))
        self.toast_text = label(name='toastText', wrap=True)
        toast_layout.addWidget(self.toast_text)
        self.toast_box.hide()
        self.setCentralWidget(root)
        self.toast_box.setParent(root)
        self.pages = dict(login=self.login_page(), register=self.register_page(), empty=self.empty_page(),
                          home=self.home_page())
        for page in self.pages.values(): self.stack.addWidget(page)
        self.setStyleSheet(sheet(self.theme))
        self.show_page(getattr(self, 'page', 'login'))

    def rebuild(self):
        # A new language or theme: the same state, drawn again.
        page, values = self.page, {name: field.text() for name, field in self.fields().items()}
        old = self.takeCentralWidget()
        old.deleteLater()
        self.build()
        for name, field in self.fields().items(): field.setText(values.get(name, ''))
        self.show_page(page)
        if page == 'home': self.draw_networks()

    def fields(self) -> dict:
        return {name: value for name, value in vars(self).items() if name.startswith('field_')}

    def top_bar(self) -> QFrame:
        t = self.texts
        bar, layout = frame('top', vertical=False, margins=(16, 10, 16, 10), spacing=10)
        layout.addWidget(label('VPN', 'brand'))
        layout.addWidget(label(f'v{__version__}', 'version'))
        self.user_pill = label(name='pill')
        layout.addWidget(self.user_pill)
        layout.addStretch(1)
        self.language = QComboBox()
        for code, name in LANGUAGES.items(): self.language.addItem(name, code)
        self.language.setCurrentIndex(list(LANGUAGES).index(self.texts.language))
        self.language.currentIndexChanged.connect(self.change_language)
        layout.addWidget(self.language)
        theme = button(t('Tema'))
        theme.clicked.connect(self.toggle_theme)
        layout.addWidget(theme)
        self.logout_button = button(t('Salir'))
        self.logout_button.clicked.connect(self.logout)
        layout.addWidget(self.logout_button)
        return bar

    def card_page(self, title: str, subtitle: str):
        # A centred card like the panel's login.
        page = QWidget()
        page.setObjectName('page')
        outer = QVBoxLayout(page)
        outer.setContentsMargins(16, 24, 16, 24)
        outer.addStretch(1)
        row = QHBoxLayout()
        row.addStretch(1)
        card, layout = frame('login', margins=(28, 18, 28, 28), spacing=0)
        card.setFixedWidth(380)
        corner = QHBoxLayout()
        corner.addWidget(label(f'VPN · v{__version__}', 'corner'))
        corner.addStretch(1)
        layout.addLayout(corner)
        layout.addSpacing(14)
        self.page_title = label(title, 'title', wrap=True)
        layout.addWidget(self.page_title)
        layout.addSpacing(4)
        self.subtitle = label(subtitle, 'subtitle', wrap=True)
        layout.addWidget(self.subtitle)
        layout.addSpacing(6)
        row.addWidget(card)
        row.addStretch(1)
        outer.addLayout(row)
        outer.addStretch(1)
        return page, layout

    def field(self, layout, name: str, text: str, secret: bool = False, value: str = '') -> QLineEdit:
        layout.addSpacing(14)
        layout.addWidget(label(text.upper(), 'label'))
        layout.addSpacing(6)
        widget = QLineEdit(value)
        if secret: widget.setEchoMode(QLineEdit.Password)
        widget.returnPressed.connect(lambda: self.submit(name))
        setattr(self, f'field_{name}', widget)
        layout.addWidget(widget)
        return widget

    def submit(self, name: str):
        if name.startswith('register'): self.register()
        elif name.startswith('login'): self.login()
        elif name == 'organization': self.create_organization()

    def login_page(self) -> QWidget:
        t = self.texts
        page, layout = self.card_page(t('Conectarse a la VPN'), t('Ingrese la dirección del servidor y su cuenta.'))
        self.field(layout, 'login_server', t('Servidor'), value=self.settings.value('server') or '')
        self.field(layout, 'login_username', t('Usuario'), value=self.settings.value('username') or '')
        self.field(layout, 'login_password', t('Contraseña'), secret=True)
        layout.addSpacing(20)
        self.login_button = button(t('Iniciar sesión'), primary=True)
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.login_button)
        layout.addSpacing(14)
        switch = button(t('¿No tiene cuenta? Crear una'))
        switch.setObjectName('flat')
        switch.clicked.connect(lambda: self.show_page('register'))
        layout.addWidget(switch, 0, Qt.AlignLeft)
        return page

    def register_page(self) -> QWidget:
        t = self.texts
        page, layout = self.card_page(t('Crear cuenta'), t('Cree su cuenta en este servidor.'))
        self.field(layout, 'register_server', t('Servidor'), value=self.settings.value('server') or '')
        self.field(layout, 'register_username', t('Usuario'))
        self.field(layout, 'register_email', t('Correo'))
        self.field(layout, 'register_password', t('Contraseña'), secret=True)
        self.field(layout, 'register_repeat', t('Repetir contraseña'), secret=True)
        layout.addSpacing(8)
        layout.addWidget(label(t('Su contraseña nunca sale de este equipo.'), 'note', wrap=True))
        layout.addSpacing(14)
        self.register_button = button(t('Crear cuenta'), primary=True)
        self.register_button.clicked.connect(self.register)
        layout.addWidget(self.register_button)
        layout.addSpacing(14)
        switch = button(t('¿Ya tiene cuenta? Iniciar sesión'))
        switch.setObjectName('flat')
        switch.clicked.connect(lambda: self.show_page('login'))
        layout.addWidget(switch, 0, Qt.AlignLeft)
        return page

    def empty_page(self) -> QWidget:
        # No networks: found an organization, or wait to be added by email.
        t = self.texts
        page, layout = self.card_page(t('Su cuenta todavía no tiene redes'), '')
        self.waiting_title, self.waiting_text = self.page_title, self.subtitle
        self.field(layout, 'organization', t('Nombre de la organización'))
        layout.addSpacing(20)
        self.found_button = button(t('Crear organización'), primary=True)
        self.found_button.clicked.connect(self.create_organization)
        layout.addWidget(self.found_button)
        layout.addSpacing(10)
        self.check_button = button(t('Volver a comprobar'))
        # Without networks it checks again; with them it goes back to the list.
        self.check_button.clicked.connect(lambda: self.show_page('home') if self.networks else self.load_networks())
        layout.addWidget(self.check_button)
        return page

    def home_page(self) -> QWidget:
        t = self.texts
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        page = QWidget()
        page.setObjectName('page')
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(0)
        layout.addWidget(label(t('Redes'), 'heading'))
        layout.addSpacing(2)
        layout.addWidget(label(t('Elija una red y conéctese.'), 'subtitle'))
        layout.addSpacing(18)
        # Status card.
        card, inner = frame('card', margins=(20, 16, 20, 18), spacing=8)
        head = QHBoxLayout()
        head.addWidget(label(t('Estado').upper(), 'section'))
        head.addStretch(1)
        self.state_tag = label(name='tag')
        head.addWidget(self.state_tag)
        inner.addLayout(head)
        self.status_rows = {}
        for key in ('Red', 'Su IP', 'Bajada', 'Subida'):
            row = QHBoxLayout()
            row.addWidget(label(t(key), 'key'))
            row.addStretch(1)
            value = label('—', 'value')
            value.setTextInteractionFlags(Qt.TextSelectableByMouse)
            row.addWidget(value)
            self.status_rows[key] = value
            inner.addLayout(row)
        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.connect_button = button(t('Conectar'), primary=True)
        self.connect_button.clicked.connect(self.toggle_connection)
        buttons.addWidget(self.connect_button, 1)
        self.panel_button = button(t('Abrir panel'))
        self.panel_button.clicked.connect(self.open_panel)
        buttons.addWidget(self.panel_button)
        inner.addSpacing(6)
        inner.addLayout(buttons)
        layout.addWidget(card)
        layout.addSpacing(18)
        # Networks card.
        card, inner = frame('card', margins=(0, 16, 0, 0), spacing=0)
        head = QHBoxLayout()
        head.setContentsMargins(20, 0, 20, 12)
        head.addWidget(label(t('Sus redes').upper(), 'section'))
        head.addStretch(1)
        self.new_button = button(t('Nueva organización'), small=True)
        self.new_button.clicked.connect(lambda: self.show_page('empty'))
        head.addWidget(self.new_button)
        inner.addLayout(head)
        self.network_list = QVBoxLayout()
        self.network_list.setSpacing(0)
        inner.addLayout(self.network_list)
        layout.addWidget(card)
        layout.addStretch(1)
        scroll.setWidget(page)
        return scroll

    # ---------- Behaviour ----------

    def show_page(self, name: str):
        self.page = name
        self.stack.setCurrentWidget(self.pages[name])
        logged = bool(self.client) and name in ('home', 'empty')
        self.logout_button.setVisible(logged)
        self.user_pill.setVisible(logged and bool(self.account.get('username')))
        self.user_pill.setText(self.account.get('email') or self.account.get('username') or '')
        if name == 'empty':
            t, email = self.texts, self.account.get('email') or ''
            waiting = t('Puede crear su propia organización o esperar a que un administrador le agregue '
                        'con su correo {email}.', email=email)
            self.waiting_title.setText(t('Nueva organización') if self.networks else t('Su cuenta todavía no tiene redes'))
            self.waiting_text.setText(t('Usted la administrará.') if self.networks else waiting)
            self.check_button.setText(t('Cancelar') if self.networks else t('Volver a comprobar'))
        if name == 'home': self.refresh_status()

    def toast(self, text: str, bad: bool = False):
        self.toast_box.setProperty('tone', 'bad' if bad else None)
        for widget in (self.toast_box, self.toast_text):
            widget.style().unpolish(widget)
            widget.style().polish(widget)
        self.toast_text.setText(text)
        self.toast_box.setFixedWidth(min(340, self.width() - 32))
        self.toast_box.adjustSize()
        self.toast_box.move(self.width() - self.toast_box.width() - 16, 64)
        self.toast_box.show()
        self.toast_box.raise_()
        QTimer.singleShot(4000, self.toast_box.hide)

    def failed(self, error):
        if isinstance(error, VPNError): self.toast(self.texts.error(error), bad=True)
        else: self.toast(str(error) or error.__class__.__name__, bad=True)

    def run(self, function, done, *arguments, busy=()):
        # One call at a time per button: it stays disabled until the server answers.
        task = Task(function, *arguments)
        self.tasks.add(task)
        for widget in busy: widget.setEnabled(False)

        def finish(handler):
            def call(value):
                self.tasks.discard(task)
                for widget in busy: widget.setEnabled(True)
                handler(value)
            return call

        task.signals.done.connect(finish(done))
        task.signals.failed.connect(finish(self.failed))
        self.pool.start(task)

    def server(self, text: str):
        try: return address(text.strip())
        except Exception:
            self.toast(self.texts('Ingrese el servidor como host o host:puerto.'), bad=True)
            return None

    def login(self):
        server = self.server(self.field_login_server.text())
        username, password = self.field_login_username.text().strip(), self.field_login_password.text()
        if not server: return
        if not username or not password: return self.toast(self.texts('Complete todos los campos.'), bad=True)
        self.settings.setValue('server', self.field_login_server.text().strip())
        self.settings.setValue('username', username)

        def work():
            client = self.client_class(server)
            client.authenticate(username, password)
            return client, client.account(), client.list_networks()

        self.run(work, self.logged_in, busy=[self.login_button])

    def register(self):
        server = self.server(self.field_register_server.text())
        username, email = self.field_register_username.text().strip(), self.field_register_email.text().strip()
        password, repeat = self.field_register_password.text(), self.field_register_repeat.text()
        if not server: return
        if not (username and email and password): return self.toast(self.texts('Complete todos los campos.'), bad=True)
        if password != repeat: return self.failed(VPNError('passwords_differ'))
        self.settings.setValue('server', self.field_register_server.text().strip())
        self.settings.setValue('username', username)

        def work():
            client = self.client_class(server)
            client.register(username, email, password)
            client.authenticate(username, password)
            return client, client.account(), client.list_networks()

        self.run(work, self.registered, busy=[self.register_button])

    def registered(self, result):
        self.toast(self.texts('Cuenta creada.'))
        self.logged_in(result)

    def logged_in(self, result):
        self.client, self.account, self.networks = result
        for name, field in self.fields().items():
            if 'password' in name or 'repeat' in name: field.clear()
        self.after_networks()

    def after_networks(self):
        # The same choice as the CLI: without networks, found an organization or wait.
        if not self.networks: return self.show_page('empty')
        default = next((network for network in self.networks if network.get('default')), self.networks[0])
        known = {network['network_id'] for network in self.networks}
        if self.selected not in known: self.selected = default['network_id']
        self.draw_networks()
        self.show_page('home')

    def load_networks(self):
        self.run(self.client.list_networks, self.loaded, busy=[self.check_button])

    def loaded(self, networks):
        self.networks = networks
        if not networks: self.toast(self.texts('Todavía sin redes.'))
        self.after_networks()

    def create_organization(self):
        name = self.field_organization.text()

        def work():
            created = self.client.create_organization(name)
            return created, self.client.list_networks()

        def done(result):
            created, self.networks = result
            self.selected = created['network_id']
            self.field_organization.clear()
            self.toast(self.texts('Organización creada.'))
            self.after_networks()

        self.run(work, done, busy=[self.found_button])

    def draw_networks(self):
        while self.network_list.count():
            widget = self.network_list.takeAt(0).widget()
            if widget: widget.deleteLater()
        t = self.texts
        for network in self.networks:
            row, layout = frame('row', vertical=False, margins=(20, 12, 20, 12), spacing=12)
            row.setProperty('selected', network['network_id'] == self.selected)
            row.setCursor(Qt.PointingHandCursor)
            names = QVBoxLayout()
            names.setSpacing(2)
            title = network.get('name') or network['network_range']
            names.addWidget(label(title, 'strong'))
            names.addWidget(label(network.get('organization') or t('Sin nombre'), 'muted'))
            layout.addLayout(names, 1)
            if network.get('default'): layout.addWidget(label(t('Principal'), 'tag'), 0, Qt.AlignVCenter)
            details = QVBoxLayout()
            details.setSpacing(2)
            for text in (network.get('ip_address') or '—', network['network_range']):
                value = label(text, 'value')
                value.setAlignment(Qt.AlignRight)
                details.addWidget(value)
            layout.addLayout(details)
            row.mousePressEvent = lambda event, network_id=network['network_id']: self.choose(network_id)
            self.network_list.addWidget(row)

    def choose(self, network_id: str):
        # While connected, choosing another network moves the tunnel there.
        if network_id == self.selected: return
        self.selected = network_id
        if self.connected(): self.client.switch(network_id)
        self.draw_networks()
        self.refresh_status()

    def connected(self) -> bool:
        return bool(self.tunnel and self.tunnel.is_alive())

    def toggle_connection(self):
        if self.connected():
            self.client.stop()
            return
        self.tunnel_error = None
        interface = self.settings.value('interface') or 'vpn0'
        self.tunnel = threading.Thread(target=self.run_tunnel, args=(interface, self.selected), daemon=True)
        self.tunnel.start()
        self.refresh_status()

    def run_tunnel(self, interface: str, network_id: str):
        # The tunnel owns the client's socket until it ends; the window only reads its status.
        try: self.client.connect(interface=interface, network_id=network_id)
        except VPNError as error: self.tunnel_error = error
        except Exception as error: self.tunnel_error = VPNError('tunnel_failed', reason=str(error))

    def refresh_status(self):
        if getattr(self, 'page', None) != 'home' or not self.client: return
        t, alive = self.texts, self.connected()
        status = self.client.status()
        if self.tunnel_error:
            error, self.tunnel_error = self.tunnel_error, None
            self.failed(error)
        if self.client.error:
            error, self.client.error = self.client.error, None
            self.failed(error)
        up = alive and status['connected']
        tone, text = ('green', t('Conectado')) if up else (('amber', t('Conectando…')) if alive else (None, t('Desconectado')))
        self.state_tag.setText(text)
        self.state_tag.setProperty('tone', tone)
        self.state_tag.style().unpolish(self.state_tag)
        self.state_tag.style().polish(self.state_tag)
        chosen = next((network for network in self.networks if network['network_id'] == self.selected), {})
        primary = next((network for network in status['networks'] if network.get('primary')), {})
        self.status_rows['Red'].setText(chosen.get('name') or chosen.get('network_range') or '—')
        self.status_rows['Su IP'].setText(primary.get('ip_address') or chosen.get('ip_address') or '—')
        self.status_rows['Bajada'].setText(speed(status['download']) if up else '—')
        self.status_rows['Subida'].setText(speed(status['upload']) if up else '—')
        self.connect_button.setText(t('Desconectar') if alive else t('Conectar'))
        self.connect_button.setProperty('primary', not alive)
        self.connect_button.setProperty('danger', alive)
        self.connect_button.style().unpolish(self.connect_button)
        self.connect_button.style().polish(self.connect_button)
        self.panel_button.setEnabled(up and bool(primary.get('server')))
        # The socket belongs to the tunnel while it runs: no other request may use it.
        self.new_button.setEnabled(not alive)

    def open_panel(self):
        status = self.client.status()
        primary = next((network for network in status['networks'] if network.get('primary')), {})
        server = primary.get('server') or {}
        if not server.get('ip_address'): return
        port = server.get('port') or 80
        suffix = '' if port == 80 else f':{port}'
        QDesktopServices.openUrl(QUrl(f"http://{server['ip_address']}{suffix}/"))

    def logout(self):
        if self.connected():
            self.client.stop()
            self.tunnel.join(5)
        self.client, self.account, self.networks, self.selected = None, {}, [], None
        self.show_page('login')

    def change_language(self, index: int):
        code = self.language.itemData(index)
        if code == self.texts.language: return
        self.settings.setValue('language', code)
        self.texts = Texts(code)
        self.rebuild()

    def toggle_theme(self):
        self.theme = 'light' if self.theme == 'dark' else 'dark'
        self.settings.setValue('theme', self.theme)
        self.setStyleSheet(sheet(self.theme))

    def closeEvent(self, event):
        # Closing the window ends the tunnel and removes its routes.
        if self.connected():
            self.client.stop()
            self.tunnel.join(5)
        super().closeEvent(event)


def main(arguments: list[str] = None) -> int:
    import sys
    from PySide6.QtWidgets import QApplication
    application = QApplication(arguments if arguments is not None else sys.argv)
    application.setApplicationName('VPN')
    window = Window()
    window.show()
    return application.exec()
