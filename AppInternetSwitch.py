import ctypes
import hashlib
import json
import os
import re
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "App Internet Switch"
APP_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "AppInternetSwitch")
CONFIG_FILE = os.path.join(APP_DIR, "apps.json")
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


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


def run_netsh(args):
    completed = subprocess.run(
        ["netsh", "advfirewall", "firewall"] + args,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        creationflags=NO_WINDOW
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "Unknown Windows Firewall error").strip()
        raise RuntimeError(detail)


def names_for_key(key):
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"AIS_{digest}_OUT", f"AIS_{digest}_IN"


def set_rule_pair(names, blocked, rule_specs):
    for name, direction, extra in (
        (names[0], "out", rule_specs),
        (names[1], "in", rule_specs),
    ):
        update = subprocess.run(
            ["netsh", "advfirewall", "firewall", "set", "rule",
             f"name={name}", "new", f"enable={'yes' if blocked else 'no'}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            creationflags=NO_WINDOW
        )
        if update.returncode != 0:
            run_netsh([
                "add", "rule", f"name={name}", f"dir={direction}", "action=block",
                *extra, "enable=yes", "profile=any",
                "description=Managed by App Internet Switch"
            ])
            if not blocked:
                run_netsh(["set", "rule", f"name={name}", "new", "enable=no"])


def set_app_blocked(path, blocked):
    names = names_for_key(os.path.normcase(os.path.abspath(path)))
    set_rule_pair(names, blocked, [f"program={os.path.abspath(path)}"])


def service_executable(path_name):
    match = re.match(r'^"([^"]+?\.exe)"|^(.+?\.exe)(?:\s|$)', path_name.strip(), re.I)
    if not match:
        return None
    path = os.path.expandvars(match.group(1) or match.group(2)).strip()
    if path.lower().startswith("\\systemroot\\"):
        path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), path[len("\\SystemRoot\\"):])
    elif path.lower().startswith("\\??\\"):
        path = path[4:]
    if not os.path.isabs(path):
        candidate = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", path)
        if os.path.isfile(candidate):
            path = candidate
    return os.path.abspath(path)


def list_services():
    ps = (
        "Get-CimInstance Win32_Service | "
        "Select-Object Name,DisplayName,State,PathName | ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        creationflags=NO_WINDOW
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "Could not read Windows services.").strip())
    raw = json.loads(result.stdout or "[]")
    if isinstance(raw, dict):
        raw = [raw]
    services = []
    for item in raw:
        name = item.get("Name") or ""
        display = item.get("DisplayName") or name
        executable = service_executable(item.get("PathName") or "")
        if name and executable:
            services.append({
                "type": "service", "name": name, "display": display,
                "state": item.get("State") or "Unknown", "path": executable
            })
    return sorted(services, key=lambda x: x["display"].casefold())


def set_service_blocked(name, executable, blocked):
    # The service= filter is essential for services hosted by shared svchost.exe.
    names = names_for_key("service:" + name.casefold())
    set_rule_pair(names, blocked, [f"program={executable}", f"service={name}"])


def remove_rules(item):
    if item.get("type", "app") == "service":
        names = names_for_key("service:" + item["name"].casefold())
    else:
        names = names_for_key(os.path.normcase(os.path.abspath(item["path"])))
    for name in names:
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            creationflags=NO_WINDOW
        )


def set_item_blocked(item, blocked):
    if item.get("type", "app") == "service":
        set_service_blocked(item["name"], item["path"], blocked)
    else:
        set_app_blocked(item["path"], blocked)


def remove_unwanted_gui_startup():
    subprocess.run(
        ["schtasks", "/Delete", "/TN", "AppInternetSwitch", "/F"],
        capture_output=True, text=True, creationflags=NO_WINDOW
    )


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("900x520")
        self.minsize(720, 430)
        self.configure(bg="#f3f5f8")
        os.makedirs(APP_DIR, exist_ok=True)
        self.apps = self.load_apps()
        self.build_ui()
        self.refresh()

    def load_apps(self):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            valid = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                kind = item.get("type", "app")
                if kind == "service":
                    if item.get("name") and item.get("path"):
                        valid.append(item)
                elif os.path.isfile(item.get("path", "")):
                    item["type"] = "app"
                    valid.append(item)
            return valid
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
        tk.Label(header, text="Control internet access for applications and Windows services.",
                 bg="#17243a", fg="#d4deed", font=("Segoe UI", 10)).pack(anchor="w", pady=(4, 0))
        body = tk.Frame(self, bg="#f3f5f8", padx=20, pady=18)
        body.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(body, columns=("kind", "status", "target"), show="headings", selectmode="browse")
        self.tree.heading("kind", text="TYPE")
        self.tree.heading("status", text="INTERNET")
        self.tree.heading("target", text="APPLICATION / SERVICE")
        self.tree.column("kind", width=100, anchor="center", stretch=False)
        self.tree.column("status", width=110, anchor="center", stretch=False)
        self.tree.column("target", width=620, anchor="w")
        self.tree.pack(fill="both", expand=True)
        buttons = tk.Frame(body, bg="#f3f5f8")
        buttons.pack(fill="x", pady=(14, 0))
        tk.Button(buttons, text="＋ Add app (.exe)", command=self.add_app,
                  bg="#2459a6", fg="white", activebackground="#1c4788",
                  activeforeground="white", relief="flat", padx=14, pady=9,
                  font=("Segoe UI", 10, "bold"), cursor="hand2").pack(side="left")
        tk.Button(buttons, text="＋ Add service", command=self.add_service,
                  bg="#344d70", fg="white", activebackground="#263d5c",
                  activeforeground="white", relief="flat", padx=14, pady=9,
                  font=("Segoe UI", 10, "bold"), cursor="hand2").pack(side="left", padx=(8, 0))
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
        tk.Label(self, text="Uses Windows Defender Firewall. Service rules target the selected service, including services hosted by svchost.exe. Administrator access is required.",
                 bg="#f3f5f8", fg="#687589", font=("Segoe UI", 9), padx=20, pady=8).pack(fill="x")

    def refresh(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for i, item in enumerate(self.apps):
            kind = item.get("type", "app")
            status = "BLOCKED" if item.get("blocked") else "ALLOWED"
            if kind == "service":
                target = f"{item.get('display', item['name'])}  ({item['name']})"
                label = "SERVICE"
            else:
                target = item["path"]
                label = "APP"
            self.tree.insert("", "end", iid=str(i), values=(label, status, target))
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
        if any(x.get("type", "app") == "app" and os.path.normcase(x["path"]) == os.path.normcase(path) for x in self.apps):
            messagebox.showinfo(APP_NAME, "This application is already in the list.")
            return
        try:
            set_app_blocked(path, False)
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Could not create firewall rules:\n{e}")
            return
        self.apps.append({"type": "app", "path": path, "blocked": False})
        self.save_apps()
        self.refresh()
        self.tree.selection_set(str(len(self.apps) - 1))

    def add_service(self):
        try:
            services = list_services()
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Could not list Windows services:\n{e}")
            return
        win = tk.Toplevel(self)
        win.title("Choose Windows service")
        win.geometry("700x480")
        win.transient(self)
        win.grab_set()
        tk.Label(win, text="Select a service whose network access you want to control.",
                 font=("Segoe UI", 10), padx=12, pady=10).pack(anchor="w")
        search = tk.StringVar()
        entry = ttk.Entry(win, textvariable=search)
        entry.pack(fill="x", padx=12, pady=(0, 8))
        listing = ttk.Treeview(win, columns=("name", "state"), show="tree headings", selectmode="browse")
        listing.heading("#0", text="SERVICE")
        listing.heading("name", text="SERVICE NAME")
        listing.heading("state", text="STATE")
        listing.column("#0", width=330)
        listing.column("name", width=190)
        listing.column("state", width=100, anchor="center")
        listing.pack(fill="both", expand=True, padx=12, pady=4)
        current = []

        def populate(*_):
            for row in listing.get_children():
                listing.delete(row)
            current.clear()
            term = search.get().casefold()
            for service in services:
                if term and term not in service["display"].casefold() and term not in service["name"].casefold():
                    continue
                current.append(service)
                listing.insert("", "end", iid=str(len(current)-1),
                               text=service["display"], values=(service["name"], service["state"]))

        def choose(_event=None):
            selected = listing.selection()
            if not selected:
                return
            service = current[int(selected[0])]
            if any(x.get("type") == "service" and x.get("name", "").casefold() == service["name"].casefold() for x in self.apps):
                messagebox.showinfo(APP_NAME, "This service is already in the list.", parent=win)
                return
            try:
                set_service_blocked(service["name"], service["path"], False)
            except Exception as e:
                messagebox.showerror(APP_NAME, f"Could not create service firewall rules:\n{e}", parent=win)
                return
            self.apps.append({
                "type": "service", "name": service["name"], "display": service["display"],
                "path": service["path"], "blocked": False
            })
            self.save_apps()
            self.refresh()
            self.tree.selection_set(str(len(self.apps) - 1))
            win.destroy()

        search.trace_add("write", populate)
        listing.bind("<Double-1>", choose)
        bottom = tk.Frame(win, padx=12, pady=10)
        bottom.pack(fill="x")
        tk.Button(bottom, text="Add selected service", command=choose, padx=12, pady=7).pack(side="right")
        tk.Label(bottom, text="Tip: search by service display name or service name.", fg="#687589").pack(side="left")
        populate()
        entry.focus_set()

    def toggle_selected(self):
        idx = self.selected_index()
        if idx is None:
            return
        item = self.apps[idx]
        new_state = not item.get("blocked", False)
        try:
            set_item_blocked(item, new_state)
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Could not update Windows Firewall:\n{e}")
            return
        item["blocked"] = new_state
        self.save_apps()
        self.refresh()
        self.tree.selection_set(str(idx))

    def remove_selected(self):
        idx = self.selected_index()
        if idx is None:
            return
        item = self.apps[idx]
        label = item.get("display", item.get("name", os.path.basename(item["path"])))
        if not messagebox.askyesno(APP_NAME, f"Remove {label} and delete its firewall rules?"):
            return
        remove_rules(item)
        self.apps.pop(idx)
        self.save_apps()
        self.refresh()


if __name__ == "__main__":
    if sys.platform != "win32":
        print("App Internet Switch is for Windows 10/11.")
        sys.exit(1)
    if not is_admin():
        relaunch_as_admin()
    remove_unwanted_gui_startup()
    App().mainloop()
