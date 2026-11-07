import ctypes
import hashlib
import json
import os
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "App Internet Switch"
APP_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "AppInternetSwitch")
CONFIG_FILE = os.path.join(APP_DIR, "apps.json")


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    params = subprocess.list2cmdline(sys.argv)
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    if result <= 32:
        messagebox.showerror(APP_NAME, "Administrator permission is required to manage Windows Firewall rules.")
    sys.exit(0)


def rule_names(path):
    key = hashlib.sha256(os.path.normcase(os.path.abspath(path)).encode("utf-8")).hexdigest()[:16]
    return f"AIS_{key}_OUT", f"AIS_{key}_IN"


def run_netsh(args):
    completed = subprocess.run(
        ["netsh", "advfirewall", "firewall"] + args,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "Unknown Windows Firewall error").strip()
        raise RuntimeError(detail)


def set_blocked(path, blocked):
    out_rule, in_rule = rule_names(path)
    for name, direction in ((out_rule, "out"), (in_rule, "in")):
        args = ["set", "rule", f"name={name}", "new", f"enable={'yes' if blocked else 'no'}"]
        p = subprocess.run(
            ["netsh", "advfirewall", "firewall"] + args,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
        if p.returncode != 0:
            run_netsh([
                "add", "rule", f"name={name}", f"dir={direction}", "action=block",
                f"program={os.path.abspath(path)}", "enable=yes",
                "profile=any", "description=Managed by App Internet Switch"
            ])
            if not blocked:
                run_netsh(["set", "rule", f"name={name}", "new", "enable=no"])


def remove_rules(path):
    for name in rule_names(path):
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )



def install_startup_task():
    """Launch the app at each Windows sign-in with the privileges needed for Firewall."""
    task_name = "AppInternetSwitch"
    query = subprocess.run(
        ["schtasks", "/Query", "/TN", task_name],
        capture_output=True, text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    if query.returncode == 0:
        return

    if getattr(sys, "frozen", False):
        command = subprocess.list2cmdline([os.path.abspath(sys.executable)])
    else:
        script = os.path.abspath(sys.argv[0])
        command = subprocess.list2cmdline([os.path.abspath(sys.executable), script])

    created = subprocess.run(
        ["schtasks", "/Create", "/TN", task_name, "/SC", "ONLOGON",
         "/RL", "HIGHEST", "/IT", "/TR", command, "/F"],
        capture_output=True, text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    if created.returncode != 0:
        detail = (created.stderr or created.stdout or "Unknown Task Scheduler error").strip()
        messagebox.showwarning(
            APP_NAME,
            "The app is running, but automatic startup could not be enabled.\\n\\n" + detail
        )

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("760x470")
        self.minsize(650, 390)
        self.configure(bg="#f3f5f8")
        os.makedirs(APP_DIR, exist_ok=True)
        self.apps = self.load_apps()
        self.build_ui()
        self.refresh()

    def load_apps(self):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return [x for x in data if isinstance(x, dict) and os.path.isfile(x.get("path", ""))]
        except (OSError, ValueError, TypeError):
            return []

    def save_apps(self):
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(self.apps, f, indent=2, ensure_ascii=False)

    def build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=34, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        header = tk.Frame(self, bg="#17243a", padx=22, pady=18)
        header.pack(fill="x")
        tk.Label(header, text="App Internet Switch", bg="#17243a", fg="white",
                 font=("Segoe UI", 19, "bold")).pack(anchor="w")
        tk.Label(header, text="Choose which Windows apps are allowed to access the internet.",
                 bg="#17243a", fg="#d4deed", font=("Segoe UI", 10)).pack(anchor="w", pady=(4, 0))
        body = tk.Frame(self, bg="#f3f5f8", padx=20, pady=18)
        body.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(body, columns=("status", "path"), show="headings", selectmode="browse")
        self.tree.heading("status", text="INTERNET")
        self.tree.heading("path", text="APPLICATION")
        self.tree.column("status", width=110, anchor="center", stretch=False)
        self.tree.column("path", width=560, anchor="w")
        self.tree.pack(fill="both", expand=True)
        buttons = tk.Frame(body, bg="#f3f5f8")
        buttons.pack(fill="x", pady=(14, 0))
        tk.Button(buttons, text="＋ Add app (.exe)", command=self.add_app,
                  bg="#2459a6", fg="white", activebackground="#1c4788",
                  activeforeground="white", relief="flat", padx=14, pady=9,
                  font=("Segoe UI", 10, "bold"), cursor="hand2").pack(side="left")
        self.toggle_btn = tk.Button(buttons, text="Turn internet OFF", command=self.toggle_selected,
                                    bg="#c64b42", fg="white", activebackground="#a83d36",
                                    activeforeground="white", relief="flat", padx=14, pady=9,
                                    font=("Segoe UI", 10, "bold"), cursor="hand2")
        self.toggle_btn.pack(side="left", padx=8)
        self.remove_btn = tk.Button(buttons, text="Remove", command=self.remove_selected,
                                    bg="#e2e7ee", fg="#263449", relief="flat", padx=14, pady=9,
                                    font=("Segoe UI", 10), cursor="hand2")
        self.remove_btn.pack(side="left")
        self.tree.bind("<<TreeviewSelect>>", self.selection_changed)
        tk.Label(self, text="Changes are applied through Windows Defender Firewall. Administrator access is required.",
                 bg="#f3f5f8", fg="#687589", font=("Segoe UI", 9), padx=20, pady=8).pack(fill="x")

    def refresh(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for i, app in enumerate(self.apps):
            status = "BLOCKED" if app.get("blocked") else "ALLOWED"
            self.tree.insert("", "end", iid=str(i), values=(status, app["path"]))
        self.selection_changed()

    def selected_index(self):
        selection = self.tree.selection()
        return int(selection[0]) if selection else None

    def selection_changed(self, _event=None):
        idx = self.selected_index()
        if idx is None or idx >= len(self.apps):
            self.toggle_btn.configure(text="Turn internet OFF", state="disabled", bg="#9aa4b2")
            self.remove_btn.configure(state="disabled")
            return
        blocked = self.apps[idx].get("blocked", False)
        self.toggle_btn.configure(text="Turn internet ON" if blocked else "Turn internet OFF",
                                  bg="#23845b" if blocked else "#c64b42", state="normal")
        self.remove_btn.configure(state="normal")

    def add_app(self):
        path = filedialog.askopenfilename(
            title="Choose an application", filetypes=[("Windows applications", "*.exe"), ("All files", "*.*")]
        )
        if not path:
            return
        path = os.path.abspath(path)
        if not path.lower().endswith(".exe"):
            messagebox.showwarning(APP_NAME, "Please choose a Windows .exe application.")
            return
        if any(os.path.normcase(x["path"]) == os.path.normcase(path) for x in self.apps):
            messagebox.showinfo(APP_NAME, "This application is already in the list.")
            return
        try:
            set_blocked(path, False)
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Could not create firewall rules:\n{e}")
            return
        self.apps.append({"path": path, "blocked": False})
        self.save_apps()
        self.refresh()
        self.tree.selection_set(str(len(self.apps) - 1))

    def toggle_selected(self):
        idx = self.selected_index()
        if idx is None:
            return
        app = self.apps[idx]
        new_state = not app.get("blocked", False)
        try:
            set_blocked(app["path"], new_state)
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Could not update Windows Firewall:\n{e}")
            return
        app["blocked"] = new_state
        self.save_apps()
        self.refresh()
        self.tree.selection_set(str(idx))

    def remove_selected(self):
        idx = self.selected_index()
        if idx is None:
            return
        app = self.apps[idx]
        if not messagebox.askyesno(APP_NAME, f"Remove {os.path.basename(app['path'])} and delete its firewall rules?"):
            return
        remove_rules(app["path"])
        self.apps.pop(idx)
        self.save_apps()
        self.refresh()


if __name__ == "__main__":
    if sys.platform != "win32":
        print("App Internet Switch is for Windows 10/11.")
        sys.exit(1)
    if not is_admin():
        relaunch_as_admin()
    install_startup_task()
    App().mainloop()
