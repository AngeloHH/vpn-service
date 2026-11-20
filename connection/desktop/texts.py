from connection.errors import MESSAGES

# Like the panel: texts are written in Spanish and each language maps them to its own.
LANGUAGES = {'es': 'Español', 'en': 'English', 'zh': '中文', 'ru': 'Русский'}

# The Spanish text of every error code; English comes from connection.errors.
ERRORS = {
    'registration_closed': 'Este servidor no permite crear cuentas',
    'invalid_username': 'El usuario necesita de 3 a 32 letras, números, puntos, guiones o guiones bajos',
    'invalid_email': 'El correo no es válido',
    'passwords_differ': 'Las contraseñas no coinciden',
    'invalid_account': 'Los datos de la cuenta no son válidos',
    'username_taken': 'Ese usuario ya existe',
    'email_taken': 'Ese correo ya tiene una cuenta',
    'too_many_registrations': 'Demasiadas cuentas nuevas desde esta dirección',
    'incorrect_credentials': 'Usuario o contraseña incorrectos',
    'too_many_attempts': 'Demasiados intentos: espere {wait} segundos',
    'invalid_server': 'El servidor no pudo demostrar que conoce su contraseña',
    'not_authenticated': 'Inicie sesión antes de continuar',
    'server_unreachable': 'El servidor no responde',
    'no_networks': 'Su cuenta todavía no tiene redes',
    'network_unavailable': 'La red no está disponible',
    'network_conflict': 'Esa red no se puede usar junto con las demás de su cuenta',
    'account_blocked': 'Su cuenta está bloqueada en esta organización',
    'account_missing': 'La cuenta no existe',
    'invalid_name': 'El nombre necesita de 1 a 40 caracteres',
    'organization_limit': 'Una cuenta puede administrar como máximo {limit} organizaciones',
    'network_lost': 'La red elegida ya no está disponible',
    'session_ended': 'Un administrador cerró esta sesión',
    'unknown_action': 'Acción desconocida',
    'tun_missing': 'Este equipo no tiene un controlador TUN para crear la interfaz de red',
    'tunnel_failed': 'No se pudo crear la interfaz de red: {reason}',
}

EN = {
    'Conectarse a la VPN': 'Connect to the VPN',
    'Ingrese la dirección del servidor y su cuenta.': 'Enter the server address and your account.',
    'Cree su cuenta en este servidor.': 'Create your account on this server.',
    'Servidor': 'Server', 'Usuario': 'Username', 'Correo': 'Email', 'Contraseña': 'Password',
    'Repetir contraseña': 'Repeat the password', 'Iniciar sesión': 'Log in', 'Crear cuenta': 'Create account',
    '¿No tiene cuenta? Crear una': 'No account? Create one', '¿Ya tiene cuenta? Iniciar sesión': 'Have an account? Log in',
    'Su contraseña nunca sale de este equipo.': 'Your password never leaves this computer.',
    'Puede crear su propia organización o esperar a que un administrador le agregue con su correo {email}.':
        'You can create your own organization or wait for an administrator to add you with your email {email}.',
    'Nombre de la organización': 'Organization name', 'Crear organización': 'Create organization',
    'Volver a comprobar': 'Check again', 'Salir': 'Log out', 'Tema': 'Theme',
    'Redes': 'Networks', 'Elija una red y conéctese.': 'Choose a network and connect.',
    'Estado': 'Status', 'Sus redes': 'Your networks', 'Conectar': 'Connect', 'Desconectar': 'Disconnect',
    'Conectado': 'Connected', 'Desconectado': 'Disconnected', 'Conectando…': 'Connecting…',
    'Red': 'Network', 'Su IP': 'Your IP', 'Rango': 'Range', 'Bajada': 'Download', 'Subida': 'Upload',
    'Principal': 'Primary', 'Abrir panel': 'Open panel', 'Nueva organización': 'New organization',
    'Organización creada.': 'Organization created.', 'Cuenta creada.': 'Account created.',
    'Todavía sin redes.': 'No networks yet.', 'Sin nombre': 'Unnamed', 'Cancelar': 'Cancel',
    'Red cambiada.': 'Network changed.', 'Comprobando…': 'Checking…',
    'Ingrese el servidor como host o host:puerto.': 'Enter the server as host or host:port.',
    'Complete todos los campos.': 'Fill in every field.',
    'Usted la administrará.': 'You will administer it.',
}

ZH = {
    'Conectarse a la VPN': '连接到 VPN',
    'Ingrese la dirección del servidor y su cuenta.': '输入服务器地址和您的账户。',
    'Cree su cuenta en este servidor.': '在此服务器上创建您的账户。',
    'Servidor': '服务器', 'Usuario': '用户名', 'Correo': '邮箱', 'Contraseña': '密码',
    'Repetir contraseña': '再次输入密码', 'Iniciar sesión': '登录', 'Crear cuenta': '创建账户',
    '¿No tiene cuenta? Crear una': '没有账户？创建一个', '¿Ya tiene cuenta? Iniciar sesión': '已有账户？登录',
    'Su contraseña nunca sale de este equipo.': '您的密码永远不会离开这台电脑。',
    'Puede crear su propia organización o esperar a que un administrador le agregue con su correo {email}.':
        '您可以创建自己的组织，或等待管理员用您的邮箱 {email} 将您加入。',
    'Nombre de la organización': '组织名称', 'Crear organización': '创建组织',
    'Volver a comprobar': '重新检查', 'Salir': '退出', 'Tema': '主题',
    'Redes': '网络', 'Elija una red y conéctese.': '选择一个网络并连接。',
    'Estado': '状态', 'Sus redes': '您的网络', 'Conectar': '连接', 'Desconectar': '断开',
    'Conectado': '已连接', 'Desconectado': '未连接', 'Conectando…': '正在连接…',
    'Red': '网络', 'Su IP': '您的 IP', 'Rango': '范围', 'Bajada': '下载', 'Subida': '上传',
    'Principal': '主要', 'Abrir panel': '打开面板', 'Nueva organización': '新建组织',
    'Organización creada.': '组织已创建。', 'Cuenta creada.': '账户已创建。',
    'Todavía sin redes.': '还没有网络。', 'Sin nombre': '未命名', 'Cancelar': '取消',
    'Red cambiada.': '网络已切换。', 'Comprobando…': '正在检查…',
    'Ingrese el servidor como host o host:puerto.': '请按 主机 或 主机:端口 的格式输入服务器。',
    'Complete todos los campos.': '请填写所有字段。',
    'Usted la administrará.': '您将管理它。',
    # Error codes.
    'Este servidor no permite crear cuentas': '此服务器不允许创建账户',
    'El usuario necesita de 3 a 32 letras, números, puntos, guiones o guiones bajos': '用户名需要 3 到 32 个字母、数字、点、连字符或下划线',
    'El correo no es válido': '邮箱无效', 'Las contraseñas no coinciden': '两次输入的密码不一致',
    'Los datos de la cuenta no son válidos': '账户信息无效', 'Ese usuario ya existe': '该用户名已存在',
    'Ese correo ya tiene una cuenta': '该邮箱已有账户', 'Demasiadas cuentas nuevas desde esta dirección': '来自此地址的新账户过多',
    'Usuario o contraseña incorrectos': '用户名或密码错误', 'Demasiados intentos: espere {wait} segundos': '尝试次数过多：请等待 {wait} 秒',
    'El servidor no pudo demostrar que conoce su contraseña': '服务器无法证明它知道您的密码',
    'Inicie sesión antes de continuar': '请先登录', 'El servidor no responde': '服务器没有响应',
    'Su cuenta todavía no tiene redes': '您的账户还没有网络', 'La red no está disponible': '该网络不可用',
    'Esa red no se puede usar junto con las demás de su cuenta': '该网络不能与您账户的其他网络同时使用',
    'Su cuenta está bloqueada en esta organización': '您的账户在此组织中已被封禁', 'La cuenta no existe': '账户不存在',
    'El nombre necesita de 1 a 40 caracteres': '名称需要 1 到 40 个字符',
    'Una cuenta puede administrar como máximo {limit} organizaciones': '一个账户最多可以管理 {limit} 个组织',
    'La red elegida ya no está disponible': '所选网络已不可用', 'Un administrador cerró esta sesión': '管理员结束了此会话',
    'Acción desconocida': '未知操作', 'Este equipo no tiene un controlador TUN para crear la interfaz de red': '这台电脑没有用于创建网络接口的 TUN 驱动',
    'No se pudo crear la interfaz de red: {reason}': '无法创建网络接口：{reason}',
}

RU = {
    'Conectarse a la VPN': 'Подключение к VPN',
    'Ingrese la dirección del servidor y su cuenta.': 'Введите адрес сервера и данные учётной записи.',
    'Cree su cuenta en este servidor.': 'Создайте учётную запись на этом сервере.',
    'Servidor': 'Сервер', 'Usuario': 'Имя пользователя', 'Correo': 'Почта', 'Contraseña': 'Пароль',
    'Repetir contraseña': 'Повторите пароль', 'Iniciar sesión': 'Войти', 'Crear cuenta': 'Создать учётную запись',
    '¿No tiene cuenta? Crear una': 'Нет учётной записи? Создать', '¿Ya tiene cuenta? Iniciar sesión': 'Уже есть учётная запись? Войти',
    'Su contraseña nunca sale de este equipo.': 'Ваш пароль никогда не покидает этот компьютер.',
    'Puede crear su propia organización o esperar a que un administrador le agregue con su correo {email}.':
        'Вы можете создать свою организацию или подождать, пока администратор добавит вас по почте {email}.',
    'Nombre de la organización': 'Название организации', 'Crear organización': 'Создать организацию',
    'Volver a comprobar': 'Проверить снова', 'Salir': 'Выйти', 'Tema': 'Тема',
    'Redes': 'Сети', 'Elija una red y conéctese.': 'Выберите сеть и подключитесь.',
    'Estado': 'Состояние', 'Sus redes': 'Ваши сети', 'Conectar': 'Подключить', 'Desconectar': 'Отключить',
    'Conectado': 'Подключено', 'Desconectado': 'Отключено', 'Conectando…': 'Подключение…',
    'Red': 'Сеть', 'Su IP': 'Ваш IP', 'Rango': 'Диапазон', 'Bajada': 'Загрузка', 'Subida': 'Отдача',
    'Principal': 'Основная', 'Abrir panel': 'Открыть панель', 'Nueva organización': 'Новая организация',
    'Organización creada.': 'Организация создана.', 'Cuenta creada.': 'Учётная запись создана.',
    'Todavía sin redes.': 'Сетей пока нет.', 'Sin nombre': 'Без названия', 'Cancelar': 'Отмена',
    'Red cambiada.': 'Сеть изменена.', 'Comprobando…': 'Проверка…',
    'Ingrese el servidor como host o host:puerto.': 'Укажите сервер как хост или хост:порт.',
    'Complete todos los campos.': 'Заполните все поля.',
    'Usted la administrará.': 'Вы будете ею управлять.',
    # Error codes.
    'Este servidor no permite crear cuentas': 'На этом сервере нельзя создавать учётные записи',
    'El usuario necesita de 3 a 32 letras, números, puntos, guiones o guiones bajos': 'Имя пользователя: от 3 до 32 букв, цифр, точек, дефисов или подчёркиваний',
    'El correo no es válido': 'Неверный адрес почты', 'Las contraseñas no coinciden': 'Пароли не совпадают',
    'Los datos de la cuenta no son válidos': 'Неверные данные учётной записи', 'Ese usuario ya existe': 'Такое имя пользователя уже занято',
    'Ese correo ya tiene una cuenta': 'Для этой почты уже есть учётная запись', 'Demasiadas cuentas nuevas desde esta dirección': 'Слишком много новых учётных записей с этого адреса',
    'Usuario o contraseña incorrectos': 'Неверное имя пользователя или пароль', 'Demasiados intentos: espere {wait} segundos': 'Слишком много попыток: подождите {wait} с',
    'El servidor no pudo demostrar que conoce su contraseña': 'Сервер не смог доказать, что знает ваш пароль',
    'Inicie sesión antes de continuar': 'Сначала войдите', 'El servidor no responde': 'Сервер не отвечает',
    'Su cuenta todavía no tiene redes': 'У вашей учётной записи пока нет сетей', 'La red no está disponible': 'Сеть недоступна',
    'Esa red no se puede usar junto con las demás de su cuenta': 'Эту сеть нельзя использовать вместе с другими сетями вашей учётной записи',
    'Su cuenta está bloqueada en esta organización': 'Ваша учётная запись заблокирована в этой организации', 'La cuenta no existe': 'Учётная запись не существует',
    'El nombre necesita de 1 a 40 caracteres': 'Название должно содержать от 1 до 40 символов',
    'Una cuenta puede administrar como máximo {limit} organizaciones': 'Одна учётная запись может управлять не более чем {limit} организациями',
    'La red elegida ya no está disponible': 'Выбранная сеть больше недоступна', 'Un administrador cerró esta sesión': 'Администратор завершил этот сеанс',
    'Acción desconocida': 'Неизвестное действие', 'Este equipo no tiene un controlador TUN para crear la interfaz de red': 'На этом компьютере нет драйвера TUN для создания сетевого интерфейса',
    'No se pudo crear la interfaz de red: {reason}': 'Не удалось создать сетевой интерфейс: {reason}',
}

# English for error codes comes from the server's own catalog.
EN.update({ERRORS[code]: MESSAGES[code] for code in ERRORS if code in MESSAGES})
DICTIONARIES = dict(en=EN, zh=ZH, ru=RU)


class Texts:
    def __init__(self, language: str = None, system: str = None):
        self.language = language if language in LANGUAGES else detect(system)

    def __call__(self, text: str, **values) -> str:
        translated = DICTIONARIES.get(self.language, {}).get(text, text)
        try: return translated.format(**values)
        except (KeyError, IndexError): return translated

    def error(self, error) -> str:
        # By code: the server's English text is only a fallback for codes this app does not know.
        if error.code in ERRORS: return self(ERRORS[error.code], **error.details)
        return error.message


def detect(system: str = None) -> str:
    # The language of the system (Qt names it like es_ES) if the app knows it; English otherwise.
    code = (system or '').lower().replace('-', '_').split('_')[0]
    return code if code in LANGUAGES else 'en'
