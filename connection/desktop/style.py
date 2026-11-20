# The panel's look (connection/admin/web/css/panel.css) in Qt style sheets:
# square corners, hairline borders, small uppercase monospace labels.
PALETTES = {
    'dark': dict(page='#0b0b0b', card='#131313', text='#a3a3a3', strong='#e6e6e6', muted='#6e6e6e',
                 face='#1b1b1b', hi='#d4d4d4', mid='#6a6a6a', lo='#3e3e3e', faint='#2a2a2a',
                 red='#ff6b6b', green='#6be0a0', blue='#6b9bff', amber='#f0b45a'),
    'light': dict(page='#f2f2ef', card='#fbfbfa', text='#57575a', strong='#18181a', muted='#8c8c90',
                  face='#ffffff', hi='#26262a', mid='#8a8a8f', lo='#b4b4b8', faint='#d4d4d6',
                  red='#e5484d', green='#30a46c', blue='#3e63dd', amber='#b7791f'),
}
SANS = '"Segoe UI", "SF Pro Text", "Helvetica Neue", "Inter", "Noto Sans", "DejaVu Sans", sans-serif'
MONO = '"SF Mono", Menlo, Consolas, "Cascadia Mono", "DejaVu Sans Mono", monospace'


def sheet(theme: str) -> str:
    c = PALETTES[theme]
    return f'''
* {{ font-family: {SANS}; font-size: 14px; color: {c['text']}; }}
QWidget#page, QStackedWidget, QScrollArea, QScrollArea > QWidget > QWidget {{ background: {c['page']}; }}
QFrame#top {{ background: {c['card']}; border: 0; border-bottom: 1px solid {c['mid']}; }}
QLabel#brand {{ color: {c['strong']}; font-weight: 600; }}
QLabel#version, QLabel#corner {{ font-family: {MONO}; font-size: 11px; color: {c['muted']}; }}
QLabel#corner {{ font-size: 10.5px; letter-spacing: 1px; }}
QLabel#pill {{ font-family: {MONO}; font-size: 11px; border: 1px solid {c['faint']}; padding: 3px 8px; }}
QFrame#card {{ background: {c['card']}; border: 1px solid {c['faint']}; }}
QFrame#login {{ background: {c['card']}; border: 1px solid {c['mid']}; }}
QLabel#title {{ color: {c['strong']}; font-size: 20px; font-weight: 600; }}
QLabel#heading {{ color: {c['strong']}; font-size: 22px; font-weight: 600; }}
QLabel#subtitle {{ font-size: 13px; }}
QLabel#label, QLabel#section {{ font-family: {MONO}; font-size: 11px; letter-spacing: 1px; color: {c['muted']}; }}
QLabel#section {{ font-size: 10.5px; }}
QLabel#key {{ font-size: 13.5px; }}
QLabel#value {{ font-family: {MONO}; font-size: 13px; color: {c['strong']}; }}
QLabel#strong {{ color: {c['strong']}; }}
QLabel#muted, QLabel#note {{ color: {c['muted']}; font-size: 12.5px; }}
QLabel#error {{ color: {c['red']}; font-size: 13px; }}
QLabel#tag {{ font-family: {MONO}; font-size: 10.5px; border: 1px solid {c['faint']}; padding: 1px 6px; }}
QLabel#tag[tone="green"] {{ color: {c['green']}; border-color: {c['green']}; }}
QLabel#tag[tone="red"] {{ color: {c['red']}; border-color: {c['red']}; }}
QLabel#tag[tone="amber"] {{ color: {c['amber']}; border-color: {c['amber']}; }}
QLabel#link {{ font-size: 13px; color: {c['strong']}; }}
QLineEdit {{ background: {c['face']}; border: 1px solid {c['lo']}; border-radius: 0; padding: 7px 9px;
             font-family: {MONO}; font-size: 13px; color: {c['strong']};
             selection-background-color: {c['strong']}; selection-color: {c['page']}; }}
QLineEdit:focus {{ border-color: {c['strong']}; }}
QLineEdit[invalid="true"] {{ border-color: {c['red']}; }}
QLineEdit:disabled {{ color: {c['muted']}; }}
QPushButton {{ font-family: {MONO}; font-size: 12px; color: {c['strong']}; background: {c['card']};
               border: 1px solid {c['mid']}; border-radius: 0; padding: 7px 12px; }}
QPushButton:hover {{ border-color: {c['strong']}; background: {c['page']}; }}
QPushButton:focus {{ outline: none; border-color: {c['strong']}; }}
QPushButton:disabled {{ color: {c['muted']}; border-color: {c['lo']}; }}
QPushButton[primary="true"] {{ background: {c['strong']}; color: {c['page']}; border-color: {c['strong']}; padding: 10px; }}
QPushButton[primary="true"]:hover {{ background: {c['hi']}; }}
QPushButton[primary="true"]:disabled {{ background: {c['lo']}; border-color: {c['lo']}; color: {c['page']}; }}
QPushButton[danger="true"] {{ color: {c['red']}; border-color: {c['red']}; }}
QPushButton[small="true"] {{ padding: 4px 8px; font-size: 11px; }}
QPushButton#flat {{ border: 0; background: transparent; padding: 2px 0; font-family: {SANS}; font-size: 13px;
                    color: {c['strong']}; text-decoration: underline; }}
QComboBox {{ font-family: {MONO}; font-size: 12px; color: {c['strong']}; background: {c['card']};
             border: 1px solid {c['mid']}; border-radius: 0; padding: 6px 10px; }}
QComboBox::drop-down {{ border: 0; width: 18px; }}
QComboBox QAbstractItemView {{ background: {c['card']}; color: {c['strong']}; border: 1px solid {c['mid']};
                               selection-background-color: {c['strong']}; selection-color: {c['page']}; }}
QFrame#row {{ background: {c['card']}; border: 0; border-top: 1px solid {c['faint']}; }}
QFrame#row[selected="true"] {{ background: {c['page']}; border-left: 2px solid {c['strong']}; }}
QFrame#row:hover {{ background: {c['page']}; }}
QFrame#rule {{ background: {c['faint']}; max-height: 1px; border: 0; }}
QFrame#toast {{ background: {c['strong']}; border: 0; }}
QFrame#toast[tone="bad"] {{ background: {c['red']}; }}
QLabel#toastText {{ color: {c['page']}; font-size: 13px; background: transparent; }}
QFrame#toast[tone="bad"] QLabel#toastText {{ color: #ffffff; }}
QScrollBar:vertical {{ background: transparent; width: 8px; }}
QScrollBar::handle:vertical {{ background: {c['lo']}; min-height: 24px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
'''
