#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tkftpserver.py
Versão: UM SERVIDOR, várias abas = múltiplos usuários + suporte à bandeja do sistema.

Principais acréscimos nesta versão:
- Um único servidor FTP (uma instância de FTPServerThread) e múltiplos usuários (uma aba = usuário).
- Ícone na bandeja (system tray) usando `pystray` + `Pillow`.
  Menu da bandeja: Iniciar / Parar servidor, Restaurar janela, Sair.
- Ao minimizar a janela, ela vai para a bandeja.
- Se a opção "Iniciar servidor ao abrir" estiver marcada (ou salva no perfil), o app inicia o servidor
  e, se a função for usada para "Iniciar com o sistema", o app pode iniciar já minimizado na bandeja.
- Fechar pelo botão de fechar da janela (X) **fecha o programa** (não fica só na bandeja).

Instalação de dependências necessárias:
  pip install pyftpdlib psutil matplotlib pystray pillow

Notas:
- Mantive a mesma lógica de autorizer/reconstrução para novos usuários; atualizei a interface para suportar
  comportamento de bandeja e minimização.
- Em alguns ambientes Linux, pystray precisa de um backend específico (por exemplo, Gtk). Geralmente funciona
  no Windows e muitas distribuições Linux.
"""

import json
import os
import threading
import queue
import time
import webbrowser
import psutil
import math
import socket
import sys
import platform
from tkinter import (
    Tk, Frame, Label, Entry, Button, END, Scrollbar, Text,
    filedialog, messagebox, StringVar, IntVar, Canvas, BooleanVar, Checkbutton
)
from tkinter import ttk
from tkinter.ttk import Separator
import logging

# pyftpdlib imports
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, ThrottledDTPHandler
from pyftpdlib.servers import FTPServer

# matplotlib for graph
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Tray icon
try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except Exception:
    TRAY_AVAILABLE = False

# ---- config ----
DEFAULT_PORT = 2121
LOG_POLL_INTERVAL = 100    # ms
SYS_POLL_INTERVAL = 1000
NET_POLL_INTERVAL = 1000
AUTO_PROFILE = "ftp_last_profile.json"
GRAPH_HISTORY = 60

# ---- logging handler for GUI ----
class GuiLogHandler(logging.Handler):
    def __init__(self, q):
        super().__init__()
        self.q = q
    def emit(self, record):
        try:
            self.q.put(self.format(record))
        except Exception:
            pass

# ---- FTP server thread (single server) ----
class FTPServerThread(threading.Thread):
    def __init__(self, authorizer_builder, address, passive_ports=None, bandwidth=None, logger=None):
        super().__init__(daemon=True)
        self.authorizer_builder = authorizer_builder
        self.address = address
        self.passive_ports = passive_ports
        self.bandwidth = bandwidth
        self.logger = logger or logging.getLogger("ftp_server")
        self._stop_event = threading.Event()
        self.server = None
        self.handler_class = FTPHandler

    def run(self):
        try:
            # build initial authorizer
            authorizer = self.authorizer_builder()
            handler = self.handler_class
            handler.authorizer = authorizer
            if self.bandwidth:
                dtp = ThrottledDTPHandler
                dtp.read_limit = self.bandwidth.get("read") or 0
                dtp.write_limit = self.bandwidth.get("write") or 0
                handler.dtp_handler = dtp
            if self.passive_ports:
                handler.passive_ports = range(self.passive_ports[0], self.passive_ports[1] + 1)

            self.server = FTPServer(self.address, handler)
            self.logger.info(f"Servidor FTP único iniciando em {self.address[0]}:{self.address[1]}")

            try:
                self.server.serve_forever(timeout=0.5)
            except TypeError:
                try:
                    self.server.serve_forever(0.5)
                except Exception:
                    self.server.serve_forever()
        except Exception as e:
            self.logger.exception("Erro no servidor FTP: %s", e)
        finally:
            try:
                if self.server:
                    self.server.close_all()
            except Exception:
                pass
            self.logger.info("Thread de servidor finalizando.")

    def stop(self):
        self.logger.info("Parando servidor...")
        self._stop_event.set()
        if self.server:
            try:
                self.server.close_all()
                self.logger.info("Servidor fechado.")
            except Exception as e:
                self.logger.exception("Erro ao fechar servidor: %s", e)

    def refresh_authorizer(self):
        try:
            new_auth = self.authorizer_builder()
            FTPHandler.authorizer = new_auth
            self.logger.info("Authorizer do servidor atualizado (novos usuários estarão ativos para novas conexões).")
        except Exception as e:
            self.logger.exception("Erro ao atualizar authorizer: %s", e)

# ---- helper: get local IP addresses ----
def get_local_ips():
    ips = set()
    try:
        hostname = socket.gethostname()
        try:
            for ip in socket.gethostbyname_ex(hostname)[2]:
                if ip and not ip.startswith("127."):
                    ips.add(ip)
        except Exception:
            pass
        try:
            for ifname, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == socket.AF_INET and a.address and not a.address.startswith("127."):
                        ips.add(a.address)
        except Exception:
            pass
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                ips.add(ip)
            s.close()
        except Exception:
            pass
    except Exception:
        pass
    ips.add("127.0.0.1")
    return sorted(list(ips))

# ---- main GUI app ----
class TKFTPServerAppSingle:
    def __init__(self, root):
        self.root = root
        self.root.title("TK FTP Server - 1 servidor (mult. usuários)")
        self.root.geometry("1120x640")

        # state
        self.tabs = {}  # tab_frame -> user data
        self.log_q = queue.Queue()
        self.logger = logging.getLogger("tkftpserver_single")
        self.logger.setLevel(logging.INFO)
        handler = GuiLogHandler(self.log_q)
        handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        self.logger.addHandler(handler)

        self.server_thread = None
        self.server_port = DEFAULT_PORT
        self.server_bandwidth = None
        self.passive_ports = None

        # tray
        self.tray_icon = None
        self.tray_thread = None
        self.in_tray = False

        # net history
        self.net_prev = psutil.net_io_counters()
        self.tx_history = [0.0] * GRAPH_HISTORY
        self.rx_history = [0.0] * GRAPH_HISTORY

        # UI: top bar: global start/stop + add/remove tab + CPU/Mem/Tx/Rx metrics
        container = Frame(root)
        container.pack(fill="both", expand=True, padx=6, pady=6)

        topbar = Frame(container)
        topbar.pack(fill="x", pady=(0,6))

        self.global_toggle_btn = Button(topbar, text="Iniciar servidor", width=16, command=self.global_toggle_server)
        self.global_toggle_btn.pack(side="left", padx=(0,6))
        self.global_toggle_btn.config(bg="#D32F2F", activebackground="#C62828")

        Button(topbar, text="Adicionar usuário (nova aba)", command=self.add_user_tab).pack(side="left", padx=(0,6))
        Button(topbar, text="Remover aba selecionada", command=self.remove_current_tab).pack(side="left", padx=(0,6))

        # auto-start on open
        self.auto_start_var = BooleanVar(value=False)
        Checkbutton(topbar, text="Iniciar servidor ao abrir", variable=self.auto_start_var).pack(side="left", padx=(8,6))
        # install startup button
        Button(topbar, text="Instalar iniciar com o sistema (Windows)", command=self.install_startup_windows).pack(side="left", padx=(8,6))

        # start minimized to tray when auto-start
        self.start_minimized_var = BooleanVar(value=False)
        Checkbutton(topbar, text="Iniciar minimizado na bandeja", variable=self.start_minimized_var).pack(side="left", padx=(8,6))

        self.cpu_label = Label(topbar, text="CPU: -- %")
        self.cpu_label.pack(side="left", padx=(12,8))
        self.mem_label = Label(topbar, text="Mem: -- MB (--)")
        self.mem_label.pack(side="left", padx=(8,12))
        self.tx_label = Label(topbar, text="Tx: -- KB/s")
        self.tx_label.pack(side="left", padx=(8,12))
        self.rx_label = Label(topbar, text="Rx: -- KB/s")
        self.rx_label.pack(side="left", padx=(8,12))

        Separator(container, orient="horizontal").pack(fill="x", pady=(6,6))

        # Middle: left = notebook (tabs), right = log + graph
        left = Frame(container, width=520)
        left.pack(side="left", fill="both", expand=False)

        # Notebook for user tabs
        self.notebook = ttk.Notebook(left)
        self.notebook.pack(fill="both", expand=True)
        # create an initial tab
        self.add_user_tab()

        # Right: log + graph
        right = Frame(container)
        right.pack(side="left", fill="both", expand=True)

        # log
        Label(right, text="Log do servidor:").pack(anchor="w")
        log_frame = Frame(right)
        log_frame.pack(fill="both", expand=True)
        self.log_text = Text(log_frame, wrap="none")
        self.log_text.pack(fill="both", expand=True)
        self.log_text.config(state="disabled")
        lbtnf = Frame(right)
        lbtnf.pack(anchor="e", pady=(6,4))
        Button(lbtnf, text="Limpar log", command=self.clear_log).pack(side="left", padx=6)
        Button(lbtnf, text="Exportar log...", command=self.export_log).pack(side="left", padx=6)

        # graph area under log
        graph_area = Frame(right, height=220)
        graph_area.pack(fill="both", expand=False, pady=(6,0))
        Label(graph_area, text="Gráfico Tx / Rx (KB/s) - global").pack(anchor="w")
        self.fig = Figure(figsize=(6,2.6), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_ylim(0, 100)
        self.ax.set_xlim(0, GRAPH_HISTORY - 1)
        self.ax.grid(True, linestyle=':', linewidth=0.5)
        self.line_tx, = self.ax.plot(range(GRAPH_HISTORY), self.tx_history, label="Tx")
        self.line_rx, = self.ax.plot(range(GRAPH_HISTORY), self.rx_history, label="Rx")
        self.ax.legend(loc="upper right", fontsize="small")
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_area)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        # start polling timers
        self.root.after(LOG_POLL_INTERVAL, self.poll_log)
        self.root.after(SYS_POLL_INTERVAL, self.update_system_usage)
        self.root.after(NET_POLL_INTERVAL, self.update_network_usage)

        # show local IPs in log at startup
        ips = get_local_ips()
        self.logger.info("Endereços IP detectados: " + ", ".join(ips))
        self.logger.info("Use ftp://<IP>:<PORT> - lembre-se de liberar firewall/adaptador VPN se usar Radmin VPN.")

        # bindings: minimize -> to tray
        self.root.bind('<Unmap>', self.on_minimize)
        # close (X) -> really quit
        self.root.protocol('WM_DELETE_WINDOW', self.on_close_window)

        # load profile (tabs)
        self.auto_load_profile()

        # if auto_start flag saved in profile or checkbox ticked, start server
        try:
            if getattr(self, 'profile_auto_start', False) or self.auto_start_var.get():
                self.start_server()
                if self.start_minimized_var.get() and TRAY_AVAILABLE:
                    self.hide_to_tray()
        except Exception:
            pass

    # ---- user-tab management (cada aba = 1 usuário) ----
    def add_user_tab(self, profile_data=None):
        tab_frame = Frame(self.notebook)
        self.notebook.add(tab_frame, text=f"Usuário {len(self.tabs)+1}")

        top = Frame(tab_frame)
        top.pack(fill="x", pady=(4,4))

        # variables
        home_var = StringVar()
        username_var = StringVar(value=f"user{len(self.tabs)+1}")
        password_var = StringVar(value="pass")
        perm_read = IntVar(value=1)
        perm_write = IntVar(value=1)
        perm_delete = IntVar(value=0)

        Label(top, text="Pasta do usuário (home)").pack(anchor="w")
        Entry(top, textvariable=home_var, width=48).pack(anchor="w")
        Button(top, text="Selecionar pasta...", command=lambda v=home_var: self.select_home(v)).pack(anchor="w", pady=(4,6))

        ufrm = Frame(top)
        ufrm.pack(fill="x", pady=(4,0))
        Label(ufrm, text="Usuário:").grid(row=0, column=0, sticky="w")
        Entry(ufrm, textvariable=username_var, width=22).grid(row=0, column=1, padx=6)
        Label(ufrm, text="Senha:").grid(row=1, column=0, sticky="w", pady=(6,0))
        Entry(ufrm, textvariable=password_var, width=22, show="*").grid(row=1, column=1, padx=6, pady=(6,0))

        permf = Frame(top)
        permf.pack(anchor="w", pady=(6,0))
        Label(permf, text="Permissões:").grid(row=0, column=0, sticky="w")
        from tkinter import Checkbutton
        Checkbutton(permf, text="Leitura", variable=perm_read).grid(row=0, column=1, sticky="w", padx=6)
        Checkbutton(permf, text="Upload", variable=perm_write).grid(row=0, column=2, sticky="w", padx=6)
        Checkbutton(permf, text="Remover", variable=perm_delete).grid(row=0, column=3, sticky="w", padx=6)

        # optional notes / commands
        Label(top, text="Comandos / instruções (referência)").pack(anchor="w")
        commands_text = Text(top, height=6, width=54)
        commands_text.pack(fill="x", pady=(4,6))
        cmdf = Frame(top)
        cmdf.pack(anchor="e", pady=(0,6))
        Button(cmdf, text="Onde achar comandos", command=self.open_commands_docs).pack(side="left", padx=6)
        Button(cmdf, text="Limpar", command=lambda t=commands_text: t.delete("1.0", END)).pack(side="left", padx=6)

        if profile_data:
            home_var.set(profile_data.get("home", ""))
            username_var.set(profile_data.get("username", username_var.get()))
            password_var.set(profile_data.get("password", ""))
            perm_string = profile_data.get("perm_string", "")
            if perm_string:
                perm_read.set(1 if any(c in perm_string for c in "lr") else 0)
                perm_write.set(1 if any(c in perm_string for c in "awfmM") else 0)
                perm_delete.set(1 if "d" in perm_string else 0)
            cmds = profile_data.get("commands", "")
            commands_text.delete("1.0", END)
            commands_text.insert("1.0", cmds)

        self.tabs[tab_frame] = {
            "home_var": home_var,
            "username_var": username_var,
            "password_var": password_var,
            "perm_read": perm_read,
            "perm_write": perm_write,
            "perm_delete": perm_delete,
            "commands_text": commands_text,
        }

        # when user edits anything, we can update the authorizer if server is running
        def on_change(*a):
            if self.server_thread and self.server_thread.is_alive():
                self.refresh_server_authorizer()
        username_var.trace_add('write', lambda *a: on_change())
        password_var.trace_add('write', lambda *a: on_change())
        home_var.trace_add('write', lambda *a: on_change())
        perm_read.trace_add('write', lambda *a: on_change())
        perm_write.trace_add('write', lambda *a: on_change())
        perm_delete.trace_add('write', lambda *a: on_change())

        self.notebook.select(tab_frame)

    def remove_current_tab(self):
        current = self.notebook.select()
        if not current:
            return
        tab_widget = self.root.nametowidget(current)
        if len(self.tabs) <= 1:
            messagebox.showwarning("Remover aba", "Deve existir pelo menos um usuário.")
            return
        self.notebook.forget(current)
        if tab_widget in self.tabs:
            del self.tabs[tab_widget]
        self.logger.info("Aba removida.")
        if self.server_thread and self.server_thread.is_alive():
            self.refresh_server_authorizer()

    # ---- global server control ----
    def build_authorizer_from_tabs(self):
        auth = DummyAuthorizer()
        for tab, s in list(self.tabs.items()):
            username = s["username_var"].get().strip()
            password = s["password_var"].get() or ""
            homedir = s["home_var"].get().strip() or os.getcwd()
            perm_string = ""
            if s["perm_read"].get():
                perm_string += "elr"
            if s["perm_write"].get():
                perm_string += "adfmwM"
            if s["perm_delete"].get():
                perm_string += "d"
            perm_string = "".join(dict.fromkeys(perm_string)) or "elr"
            try:
                if not os.path.isdir(homedir):
                    os.makedirs(homedir, exist_ok=True)
                auth.add_user(username, password, homedir=homedir, perm=perm_string)
            except Exception as e:
                self.logger.exception("Erro ao adicionar usuário %s: %s", username, e)
        return auth

    def start_server(self):
        if self.server_thread and self.server_thread.is_alive():
            self.logger.info("Servidor já está rodando.")
            return
        try:
            port = int(self.server_port)
        except Exception:
            port = DEFAULT_PORT
        addr = ("0.0.0.0", port)
        self.server_thread = FTPServerThread(
            authorizer_builder=self.build_authorizer_from_tabs,
            address=addr,
            passive_ports=self.passive_ports,
            bandwidth=self.server_bandwidth,
            logger=self.logger
        )
        self.server_thread.start()
        self.global_toggle_btn.config(text="Parar servidor", bg="#4CAF50", activebackground="#45A049")
        ips = get_local_ips()
        for ip in ips:
            self.logger.info(f"  ftp://{ip}:{port} (users: {len(self.tabs)})")

    def stop_server(self):
        if not (self.server_thread and self.server_thread.is_alive()):
            self.logger.info("Servidor não está rodando.")
            return
        try:
            self.server_thread.stop()
            self.server_thread.join(timeout=3.0)
        except Exception:
            pass
        self.server_thread = None
        self.global_toggle_btn.config(text="Iniciar servidor", bg="#D32F2F", activebackground="#C62828")
        self.logger.info("Servidor parado.")

    def global_toggle_server(self):
        if self.server_thread and self.server_thread.is_alive():
            self.stop_server()
        else:
            self.start_server()

    def refresh_server_authorizer(self):
        if self.server_thread and self.server_thread.is_alive():
            try:
                self.server_thread.refresh_authorizer()
            except Exception:
                pass

    # ---- tray / window behavior ----
    def create_tray_icon(self):
        if not TRAY_AVAILABLE:
            self.logger.warning("pystray/Pillow não disponível: bandeja não funciona")
            return
        # small square icon
        image = Image.new('RGB', (64, 64), color=(30,30,30))
        d = ImageDraw.Draw(image)
        d.ellipse((8,8,56,56), fill=(70,130,180))
        d.text((20,20), "F", fill=(255,255,255))

        menu = (
            pystray.MenuItem('Iniciar servidor', lambda _: self._tray_start()),
            pystray.MenuItem('Parar servidor', lambda _: self._tray_stop()),
            pystray.MenuItem('Restaurar janela', lambda _: self._tray_restore()),
            pystray.MenuItem('Sair', lambda _: self._tray_quit())
        )
        self.tray_icon = pystray.Icon("tkftpserver", image, "TK FTP Server", menu)

    def _tray_start(self):
        # chamado pela thread de tray, prox. loop, então use after para garantir execução na thread tkinter
        self.root.after(0, lambda: self.start_server())

    def _tray_stop(self):
        self.root.after(0, lambda: self.stop_server())

    def _tray_restore(self):
        self.root.after(0, lambda: self.show_window())

    def _tray_quit(self):
        # para garantir fechamento limpo
        def do_quit():
            try:
                self.auto_save_profile()
            except Exception:
                pass
            self.close_all_servers()
            if self.tray_icon:
                try:
                    self.tray_icon.stop()
                except Exception:
                    pass
            self.root.destroy()
        self.root.after(0, do_quit)

    def start_tray(self):
        if not TRAY_AVAILABLE:
            return
        if self.tray_icon is None:
            self.create_tray_icon()
        if self.tray_thread and self.tray_thread.is_alive():
            return
        def run_icon():
            try:
                self.tray_icon.run()
            except Exception as e:
                self.logger.exception("Erro no loop da bandeja: %s", e)
        self.tray_thread = threading.Thread(target=run_icon, daemon=True)
        self.tray_thread.start()

    def stop_tray(self):
        if self.tray_icon:
            try:
                self.tray_icon.stop()
            except Exception:
                pass
            self.tray_icon = None
        self.tray_thread = None

    def hide_to_tray(self):
        if not TRAY_AVAILABLE:
            self.logger.warning("Bandeja indisponível (pystray/Pillow não instalado).")
            return
        if not self.in_tray:
            self.start_tray()
            try:
                self.root.withdraw()
                self.in_tray = True
                self.logger.info("Janela ocultada para bandeja.")
            except Exception:
                pass

    def show_window(self):
        try:
            self.root.deiconify()
            self.root.lift()
            self.in_tray = False
            # stop the tray icon when window is visible
            self.stop_tray()
        except Exception:
            pass

    def on_minimize(self, event):
        # event.widget == root; when minimized (iconified) => hide to tray
        try:
            if self.root.state() == 'iconic':
                # minimize -> to tray
                self.hide_to_tray()
        except Exception:
            pass

    def on_close_window(self):
        # fechar deve realmente encerrar o app
        if messagebox.askokcancel("Sair", "Deseja sair e fechar o servidor?"):
            try:
                self.auto_save_profile()
            except Exception:
                pass
            self.close_all_servers()
            # ensure tray stopped
            if self.tray_icon:
                try:
                    self.tray_icon.stop()
                except Exception:
                    pass
            self.root.destroy()

    # ---- utilities ----
    def select_home(self, var):
        p = filedialog.askdirectory(title="Selecionar pasta raiz do usuário")
        if p:
            var.set(p)

    def open_commands_docs(self):
        url = "https://pyftpdlib.readthedocs.io/en/latest/index.html"
        try:
            webbrowser.open(url)
        except Exception:
            messagebox.showinfo("Link", f"Acesse: {url}")

    def install_startup_windows(self):
        if platform.system().lower() != 'windows':
            messagebox.showinfo("Startup", "Instalação automática disponível apenas para Windows nesta versão. Use systemd/cron/LaunchAgents em Linux/Mac.")
            return
        try:
            startup = os.path.join(os.environ.get('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
            if not os.path.isdir(startup):
                messagebox.showerror("Startup", "Pasta Startup não encontrada.")
                return
            script = os.path.abspath(sys.argv[0])
            pythonw = os.path.join(sys.exec_prefix, 'pythonw.exe') if getattr(sys, 'exec_prefix', None) else 'pythonw'
            if not os.path.isfile(pythonw):
                pythonw = sys.executable
            bat_path = os.path.join(startup, 'start_tkftpserver.bat')
            # if start_minimized_var is set, add a sentinel argument --minimize
            minimize_flag = '--minimized' if self.start_minimized_var.get() else ''
            with open(bat_path, 'w', encoding='utf-8') as f:
                f.write(f'@echo off\n"{pythonw}" "{script}" {minimize_flag}\n')
            messagebox.showinfo("Startup", f"Arquivo criado: {bat_path}\nO programa será iniciado no próximo login do usuário.")
            self.logger.info(f"Criado atalho de inicialização: {bat_path}")
        except Exception as e:
            self.logger.exception("Erro ao criar atalho de inicialização: %s", e)
            messagebox.showerror("Startup", f"Erro: {e}")

    # ---- global network/system updates ----
    def update_system_usage(self):
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            used_mb = (mem.total - mem.available) / (1024 * 1024)
            self.cpu_label.config(text=f"CPU: {cpu:.0f} %")
            self.mem_label.config(text=f"Mem: {used_mb:.0f} MB ({mem.percent}%)")
        except Exception:
            pass
        finally:
            self.root.after(SYS_POLL_INTERVAL, self.update_system_usage)

    def update_network_usage(self):
        try:
            now = psutil.net_io_counters()
            tx_bytes = now.bytes_sent - self.net_prev.bytes_sent
            rx_bytes = now.bytes_recv - self.net_prev.bytes_recv
            self.net_prev = now
            kb_s_tx = (tx_bytes / 1024.0) / (NET_POLL_INTERVAL / 1000.0)
            kb_s_rx = (rx_bytes / 1024.0) / (NET_POLL_INTERVAL / 1000.0)
            self.tx_label.config(text=f"Tx: {kb_s_tx:.1f} KB/s")
            self.rx_label.config(text=f"Rx: {kb_s_rx:.1f} KB/s")

            # history update
            self.tx_history.pop(0)
            self.rx_history.pop(0)
            self.tx_history.append(max(0.0, kb_s_tx))
            self.rx_history.append(max(0.0, kb_s_rx))
            max_val = max(max(self.tx_history), max(self.rx_history), 1.0)
            y_max = max(16, math.ceil(max_val * 1.2))
            self.ax.set_ylim(0, y_max)
            x = list(range(len(self.tx_history)))
            self.line_tx.set_data(x, self.tx_history)
            self.line_rx.set_data(x, self.rx_history)
            self.ax.set_xlim(0, len(self.tx_history)-1)
            self.canvas.draw_idle()
        except Exception:
            pass
        finally:
            self.root.after(NET_POLL_INTERVAL, self.update_network_usage)

    # ---- log ----
    def poll_log(self):
        while not self.log_q.empty():
            try:
                msg = self.log_q.get_nowait()
            except Exception:
                break
            self.log_text.config(state="normal")
            self.log_text.insert(END, msg + "\n")
            self.log_text.see(END)
            self.log_text.config(state="disabled")
        self.root.after(LOG_POLL_INTERVAL, self.poll_log)

    def clear_log(self):
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", END)
        self.log_text.config(state="disabled")

    def export_log(self):
        fn = filedialog.asksaveasfilename(title="Salvar log como...", defaultextension=".txt", filetypes=[("Text files","*.txt")])
        if fn:
            text = self.log_text.get("1.0", END)
            with open(fn, "w", encoding="utf-8") as f:
                f.write(text)
            messagebox.showinfo("Exportado", f"Log salvo em {fn}")

    # ---- auto save / load for multi tabs ----
    def auto_load_profile(self):
        if os.path.exists(AUTO_PROFILE):
            try:
                with open(AUTO_PROFILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                tabs = data.get("tabs", [])
                for tab in list(self.notebook.tabs()):
                    w = self.root.nametowidget(tab)
                    self.notebook.forget(w)
                self.tabs.clear()
                for i, tdata in enumerate(tabs):
                    self.add_user_tab(profile_data=tdata)
                if not tabs:
                    self.add_user_tab()
                self.profile_auto_start = data.get("auto_start", False)
                self.start_minimized_var.set(data.get("start_minimized", False))
                self.logger.info("Auto profile (usuarios) carregado.")
            except Exception as e:
                self.logger.exception("Erro ao carregar auto profile: %s", e)

    def auto_save_profile(self):
        data = {"tabs": [], "auto_start": bool(self.auto_start_var.get()), "start_minimized": bool(self.start_minimized_var.get())}
        for tab_widget, s in list(self.tabs.items()):
            tabdata = {
                "home": s["home_var"].get(),
                "username": s["username_var"].get(),
                "password": s["password_var"].get(),
                "perm_string": "".join([
                    ("elr" if s["perm_read"].get() else ""),
                    ("adfmwM" if s["perm_write"].get() else ""),
                    ("d" if s["perm_delete"].get() else "")
                ]),
                "commands": s["commands_text"].get("1.0", END)
            }
            data["tabs"].append(tabdata)
        try:
            with open(AUTO_PROFILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.logger.info("Auto profile (usuarios) salvo.")
        except Exception as e:
            self.logger.exception("Erro ao auto-salvar profile: %s", e)

    # ---- on close handler ----
    def close_all_servers(self):
        if self.server_thread and self.server_thread.is_alive():
            try:
                self.server_thread.stop()
                self.server_thread.join(timeout=2.0)
            except Exception:
                pass
            self.server_thread = None

# ---- main & close handler ----
def main():
    root = Tk()
    # if script started with --minimized, we set the flag to hide after init
    minimized_flag = '--minimized' in sys.argv
    app = TKFTPServerAppSingle(root)
    # if started with minimized flag, hide after init
    if minimized_flag and TRAY_AVAILABLE:
        # ensure tray icon available and then hide
        app.start_server() if app.auto_start_var.get() or getattr(app, 'profile_auto_start', False) else None
        app.hide_to_tray()
    root.protocol("WM_DELETE_WINDOW", on_close_factory(root, app))
    root.mainloop()

def on_close_factory(root, app):
    def _on_close():
        try:
            app.auto_save_profile()
        except Exception:
            pass
        app.close_all_servers()
        if app.tray_icon:
            try:
                app.tray_icon.stop()
            except Exception:
                pass
        root.destroy()
    return _on_close

if __name__ == "__main__":
    main()
