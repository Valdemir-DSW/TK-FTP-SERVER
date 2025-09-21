#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tkftpserver.py
Versão com múltiplos servidores (abas) + exibição de IPs no log.

Funcionalidades principais:
- Multi-aba: crie várias abas (cada uma representa um servidor independente)
- Cada aba tem: pasta, porta, usuário, senha, limites de banda, permissões, botão Iniciar/Parar (verde/vermelho)
- Log mostra IPs locais ao abrir e URLs possíveis ao iniciar servidores
- Indicadores CPU / Memória / Tx / Rx e gráfico global Tx/Rx
- Auto-save/load de todas as abas em ftp_last_profile.json
- Requisitos: pyftpdlib, psutil, matplotlib
    pip install pyftpdlib psutil matplotlib
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
from tkinter import (
    Tk, Frame, Label, Entry, Button, END, Scrollbar, Text,
    filedialog, messagebox, StringVar, IntVar, Canvas
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

# ---- config ----
DEFAULT_PORT = 2121
LOG_POLL_INTERVAL = 100    # ms, log polling
SYS_POLL_INTERVAL = 1000   # ms, cpu/mem update
NET_POLL_INTERVAL = 1000   # ms, net io update (Tx/Rx)
AUTO_PROFILE = "ftp_last_profile.json"
GRAPH_HISTORY = 60         # points to keep in graph

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

# ---- FTP server thread ----
class FTPServerThread(threading.Thread):
    def __init__(self, authorizer, address, passive_ports=None, bandwidth=None, logger=None):
        super().__init__(daemon=True)
        self.authorizer = authorizer
        self.address = address
        self.passive_ports = passive_ports
        self.bandwidth = bandwidth
        self.logger = logger or logging.getLogger("ftp_server")
        self._stop_event = threading.Event()
        self.server = None

    def run(self):
        try:
            handler = FTPHandler
            handler.authorizer = self.authorizer
            if self.bandwidth:
                dtp = ThrottledDTPHandler
                dtp.read_limit = self.bandwidth.get("read") or 0
                dtp.write_limit = self.bandwidth.get("write") or 0
                handler.dtp_handler = dtp
            if self.passive_ports:
                handler.passive_ports = range(self.passive_ports[0], self.passive_ports[1] + 1)

            self.server = FTPServer(self.address, handler)
            self.logger.info(f"Servidor iniciando em {self.address[0]}:{self.address[1]}")
            while not self._stop_event.is_set():
                try:
                    self.server.timeout = 0.5
                    self.server.serve_forever(timeout=0.5, blocking=False)
                except TypeError:
                    self.server.serve_forever()
                time.sleep(0.01)
        except Exception as e:
            self.logger.exception("Erro no servidor FTP: %s", e)
        finally:
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

# ---- helper: get local IP addresses ----
def get_local_ips():
    ips = set()
    try:
        # host-based
        hostname = socket.gethostname()
        try:
            for ip in socket.gethostbyname_ex(hostname)[2]:
                if ip and not ip.startswith("127."):
                    ips.add(ip)
        except Exception:
            pass
        # use interfaces via psutil if available
        try:
            for ifname, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if a.family == socket.AF_INET and a.address and not a.address.startswith("127."):
                        ips.add(a.address)
        except Exception:
            pass
        # fallback: connect to public DNS and read socket name
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
    # always include loopback for local testing
    ips.add("127.0.0.1")
    return sorted(list(ips))

# ---- main GUI app ----
class TKFTPServerAppMulti:
    def __init__(self, root):
        self.root = root
        self.root.title("TK FTP Server (multi)")
        self.root.geometry("1120x640")

        # state
        self.servers = {}  # tab_id -> dict{thread,widgets, running}
        self.log_q = queue.Queue()
        self.logger = logging.getLogger("tkftpserver_multi")
        self.logger.setLevel(logging.INFO)
        handler = GuiLogHandler(self.log_q)
        handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        self.logger.addHandler(handler)

        # net history
        self.net_prev = psutil.net_io_counters()
        self.tx_history = [0.0] * GRAPH_HISTORY
        self.rx_history = [0.0] * GRAPH_HISTORY

        # UI: top bar: add/remove tab + CPU/Mem/Tx/Rx metrics
        container = Frame(root)
        container.pack(fill="both", expand=True, padx=6, pady=6)

        topbar = Frame(container)
        topbar.pack(fill="x", pady=(0,6))

        Button(topbar, text="Adicionar servidor (nova aba)", command=self.add_server_tab).pack(side="left", padx=(0,6))
        Button(topbar, text="Remover aba selecionada", command=self.remove_current_tab).pack(side="left", padx=(0,6))

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

        # Notebook for server tabs
        self.notebook = ttk.Notebook(left)
        self.notebook.pack(fill="both", expand=True)
        # create an initial tab
        self.add_server_tab()  # first tab

        # Right: log + graph
        right = Frame(container)
        right.pack(side="left", fill="both", expand=True)

        # log
        Label(right, text="Log do(s) servidor(es):").pack(anchor="w")
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

        # load profile (tabs)
        self.auto_load_profile()

    # ---- tab management ----
    def add_server_tab(self, profile_data=None):
        """Cria uma nova aba (servidor). profile_data opcional para carregar."""
        tab_frame = Frame(self.notebook)
        tab_id = f"tab{len(self.servers)+1}"
        self.notebook.add(tab_frame, text=f"Servidor {len(self.servers)+1}")
        # widgets per tab: toggle button (top of tab), controls in scrollable canvas
        top = Frame(tab_frame)
        top.pack(fill="x", pady=(4,4))
        toggle_btn = Button(top, text="Iniciar Servidor", width=16)
        toggle_btn.pack(side="left", padx=(6,8))
        # set initial color (stopped = red)
        toggle_btn.config(bg="#D32F2F", activebackground="#C62828")

        # Pack controls in scrollable canvas inside this tab
        canvas = Canvas(tab_frame, borderwidth=0, height=380)
        vsb = Scrollbar(tab_frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = Frame(canvas)
        canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e, c=canvas: c.configure(scrollregion=c.bbox("all")))

        # variables for this tab
        home_var = StringVar()
        port_var = StringVar(value=str(DEFAULT_PORT))
        username_var = StringVar(value="user")
        password_var = StringVar(value="pass")
        read_kb = StringVar(value="0")
        write_kb = StringVar(value="0")
        perm_read = IntVar(value=1)
        perm_write = IntVar(value=1)
        perm_delete = IntVar(value=0)

        # fill with controls
        Label(inner, text="Pasta do servidor (home)").pack(anchor="w")
        Entry(inner, textvariable=home_var, width=48).pack(anchor="w")
        Button(inner, text="Selecionar pasta...", command=lambda v=home_var: self.select_home(v)).pack(anchor="w", pady=(4,6))

        Label(inner, text="Porta:").pack(anchor="w")
        Entry(inner, textvariable=port_var, width=12).pack(anchor="w", pady=(0,6))

        Label(inner, text="Limite de banda (KB/s, 0 = sem limitação)").pack(anchor="w")
        bwf = Frame(inner)
        bwf.pack(anchor="w", pady=(0,6))
        Label(bwf, text="Leitura").grid(row=0, column=0)
        Entry(bwf, textvariable=read_kb, width=8).grid(row=0, column=1, padx=6)
        Label(bwf, text="Gravação").grid(row=0, column=2)
        Entry(bwf, textvariable=write_kb, width=8).grid(row=0, column=3, padx=6)

        Separator(inner, orient="horizontal").pack(fill="x", pady=6)

        Label(inner, text="Usuário padrão nesta aba").pack(anchor="w")
        ufrm = Frame(inner)
        ufrm.pack(fill="x", pady=(4,0))
        Label(ufrm, text="Usuário:").grid(row=0, column=0, sticky="w")
        Entry(ufrm, textvariable=username_var, width=22).grid(row=0, column=1, padx=6)
        Label(ufrm, text="Senha:").grid(row=1, column=0, sticky="w", pady=(6,0))
        Entry(ufrm, textvariable=password_var, width=22, show="*").grid(row=1, column=1, padx=6, pady=(6,0))

        permf = Frame(inner)
        permf.pack(anchor="w", pady=(6,0))
        Label(permf, text="Permissões:").grid(row=0, column=0, sticky="w")
        from tkinter import Checkbutton
        Checkbutton(permf, text="Leitura", variable=perm_read).grid(row=0, column=1, sticky="w", padx=6)
        Checkbutton(permf, text="Upload", variable=perm_write).grid(row=0, column=2, sticky="w", padx=6)
        Checkbutton(permf, text="Remover", variable=perm_delete).grid(row=0, column=3, sticky="w", padx=6)

        Separator(inner, orient="horizontal").pack(fill="x", pady=6)

        Label(inner, text="Comandos / instruções (referência)").pack(anchor="w")
        commands_text = Text(inner, height=6, width=54)
        commands_text.pack(fill="x", pady=(4,6))
        cmdf = Frame(inner)
        cmdf.pack(anchor="e", pady=(0,6))
        Button(cmdf, text="Onde achar comandos", command=self.open_commands_docs).pack(side="left", padx=6)
        Button(cmdf, text="Limpar", command=lambda t=commands_text: t.delete("1.0", END)).pack(side="left", padx=6)

        # if profile_data passed, load into vars
        if profile_data:
            home_var.set(profile_data.get("home", ""))
            port_var.set(str(profile_data.get("port", DEFAULT_PORT)))
            username_var.set(profile_data.get("username", "user"))
            password_var.set(profile_data.get("password", ""))
            read_kb.set(str(profile_data.get("read_kb", "0")))
            write_kb.set(str(profile_data.get("write_kb", "0")))
            perm_string = profile_data.get("perm_string", "")
            if perm_string:
                perm_read.set(1 if any(c in perm_string for c in "lr") else 0)
                perm_write.set(1 if any(c in perm_string for c in "awfmM") else 0)
                perm_delete.set(1 if "d" in perm_string else 0)
            cmds = profile_data.get("commands", "")
            commands_text.delete("1.0", END)
            commands_text.insert("1.0", cmds)

        # store tab state
        self.servers[tab_frame] = {
            "thread": None,
            "toggle_btn": toggle_btn,
            "home_var": home_var,
            "port_var": port_var,
            "username_var": username_var,
            "password_var": password_var,
            "read_kb": read_kb,
            "write_kb": write_kb,
            "perm_read": perm_read,
            "perm_write": perm_write,
            "perm_delete": perm_delete,
            "commands_text": commands_text,
            "running": False,
            "widgets_frame": tab_frame  # reference
        }

        # bind toggle action
        toggle_btn.config(command=lambda tf=tab_frame: self.tab_toggle_server(tf))

        # select newly created tab
        self.notebook.select(tab_frame)

    def remove_current_tab(self):
        current = self.notebook.select()
        if not current:
            return
        tab_widget = self.root.nametowidget(current)
        state = self.servers.get(tab_widget, {})
        if state.get("running"):
            messagebox.showwarning("Remover aba", "Pare o servidor nesta aba antes de remover.")
            return
        idx = self.notebook.index(current)
        self.notebook.forget(idx)
        # remove from servers dict
        if tab_widget in self.servers:
            del self.servers[tab_widget]
        self.logger.info(f"Aba {idx+1} removida.")

    # ---- per-tab server controls ----
    def tab_toggle_server(self, tab_widget):
        state = self.servers.get(tab_widget)
        if not state:
            return
        if state["running"]:
            self.tab_stop_server(tab_widget)
        else:
            success = self.tab_start_server(tab_widget)
            if success:
                # mark running
                pass

    def tab_start_server(self, tab_widget):
        s = self.servers.get(tab_widget)
        if not s:
            return False
        # read config
        try:
            port = int(s["port_var"].get())
            if not (1 <= port <= 65535):
                raise ValueError
        except Exception:
            messagebox.showwarning("Porta inválida", "Informe uma porta válida (1-65535) na aba selecionada.")
            return False
        base_dir = s["home_var"].get().strip()
        if not base_dir or not os.path.isdir(base_dir):
            messagebox.showwarning("Home inválida", "Defina a pasta padrão do servidor e garanta que exista.")
            return False
        username = s["username_var"].get().strip()
        if not username:
            messagebox.showwarning("Usuário inválido", "Defina um nome de usuário nesta aba.")
            return False
        password = s["password_var"].get() or ""
        # perms
        perm_string = ""
        if s["perm_read"].get():
            perm_string += "elr"
        if s["perm_write"].get():
            perm_string += "adfmwM"
        if s["perm_delete"].get():
            perm_string += "d"
        perm_string = "".join(dict.fromkeys(perm_string)) or "elr"
        authorizer = DummyAuthorizer()
        try:
            authorizer.add_user(username, password, homedir=base_dir, perm=perm_string)
        except Exception as e:
            self.logger.exception("Erro ao adicionar usuário na aba: %s", e)
            messagebox.showerror("Erro", f"Erro ao configurar usuário nesta aba: {e}")
            return False
        # bandwidth
        try:
            read_kb = int(s["read_kb"].get() or 0)
            write_kb = int(s["write_kb"].get() or 0)
        except Exception:
            messagebox.showwarning("Banda inválida", "Defina valores numéricos para banda.")
            return False
        bandwidth = None
        if read_kb or write_kb:
            bandwidth = {"read": read_kb * 1024, "write": write_kb * 1024}
        addr = ("0.0.0.0", port)
        passive_ports = None

        # create thread
        thread = FTPServerThread(
            authorizer=authorizer,
            address=addr,
            passive_ports=passive_ports,
            bandwidth=bandwidth,
            logger=self.logger
        )
        thread.start()
        s["thread"] = thread
        s["running"] = True
        # update toggle btn color/text and disable widgets in this tab
        s["toggle_btn"].config(text="Parar Servidor", bg="#4CAF50", activebackground="#45A049")
        self._set_tab_controls_enabled(tab_widget, enabled=False)
        # log IPs and possible urls
        ips = get_local_ips()
        self.logger.info(f"Servidor nesta aba iniciado na porta {port}. URLs possíveis:")
        for ip in ips:
            self.logger.info(f"  ftp://{ip}:{port} (user: {username})")
        return True

    def tab_stop_server(self, tab_widget):
        s = self.servers.get(tab_widget)
        if not s or not s.get("running"):
            messagebox.showinfo("Servidor", "Servidor desta aba não está rodando.")
            return
        thread = s.get("thread")
        if thread:
            thread.stop()
            thread.join(timeout=3.0)
        s["thread"] = None
        s["running"] = False
        s["toggle_btn"].config(text="Iniciar Servidor", bg="#D32F2F", activebackground="#C62828")
        self._set_tab_controls_enabled(tab_widget, enabled=True)
        self.logger.info("Servidor desta aba parado.")

    def _set_tab_controls_enabled(self, tab_widget, enabled: bool):
        # disable/enable inputs inside the tab (except the toggle button)
        def walk(w):
            for child in w.winfo_children():
                # skip toggle button
                if child is self.servers[tab_widget]["toggle_btn"]:
                    continue
                try:
                    # allow log and top-level buttons to remain enabled
                    child_state = "normal" if enabled else "disabled"
                    if child.winfo_class() == "Text":
                        if enabled:
                            child.config(state="normal")
                        else:
                            child.config(state="disabled")
                    else:
                        try:
                            child.config(state=child_state)
                        except Exception:
                            pass
                except Exception:
                    pass
                walk(child)
        walk(tab_widget)

    # ---- utilities ----
    def select_home(self, var):
        p = filedialog.askdirectory(title="Selecionar pasta raiz do servidor")
        if p:
            var.set(p)

    def open_commands_docs(self):
        url = "https://pyftpdlib.readthedocs.io/en/latest/index.html"
        try:
            webbrowser.open(url)
        except Exception:
            messagebox.showinfo("Link", f"Acesse: {url}")

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
            # dynamic y-limit
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
                # remove initial empty tab added earlier
                # clear existing tabs
                for tab in self.notebook.tabs():
                    w = self.root.nametowidget(tab)
                    self.notebook.forget(w)
                self.servers.clear()
                # recreate tabs from profile
                for i, tdata in enumerate(tabs):
                    self.add_server_tab(profile_data=tdata)
                if not tabs:
                    self.add_server_tab()
                self.logger.info("Auto profile (abas) carregado.")
            except Exception as e:
                self.logger.exception("Erro ao carregar auto profile: %s", e)

    def auto_save_profile(self):
        data = {"tabs": []}
        for tab_widget, s in list(self.servers.items()):
            tabdata = {
                "home": s["home_var"].get(),
                "port": s["port_var"].get(),
                "username": s["username_var"].get(),
                "password": s["password_var"].get(),
                "read_kb": s["read_kb"].get(),
                "write_kb": s["write_kb"].get(),
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
            self.logger.info("Auto profile (abas) salvo.")
        except Exception as e:
            self.logger.exception("Erro ao auto-salvar profile: %s", e)

    # ---- on close handler ----
    def close_all_servers(self):
        # stop any running servers
        for tab_widget, s in list(self.servers.items()):
            if s.get("running"):
                try:
                    thread = s.get("thread")
                    if thread:
                        thread.stop()
                        thread.join(timeout=2.0)
                except Exception:
                    pass
                s["running"] = False
                s["thread"] = None

# ---- main & close handler ----
def main():
    root = Tk()
    app = TKFTPServerAppMulti(root)
    root.protocol("WM_DELETE_WINDOW", on_close_factory(root, app))
    root.mainloop()

def on_close_factory(root, app):
    def _on_close():
        # save profile
        try:
            app.auto_save_profile()
        except Exception:
            pass
        # stop servers
        app.close_all_servers()
        root.destroy()
    return _on_close

if __name__ == "__main__":
    main()
