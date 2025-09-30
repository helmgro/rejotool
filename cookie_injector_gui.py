import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import requests

class CookieInjectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cookie Injector")
        self.root.geometry("600x400")
        self.root.resizable(False, False)
        
        tk.Label(root, text="Cookie Injector", font=("Arial", 18, "bold")).pack(pady=10)
        self.text_area = scrolledtext.ScrolledText(root, width=70, height=15, font=("Consolas", 10))
        self.text_area.pack(pady=10)
        
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="1. Inject Cookies", command=self.inject_cookies, width=20).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="2. Logout All", command=self.logout_all, width=20).pack(side=tk.LEFT, padx=10)
        
        self.cookies = []
        self.accounts = []

    def open_file(self):
        file_path = filedialog.askopenfilename(title="Select cookies.txt", filetypes=[("Text Files", "*.txt")])
        return file_path

    def read_cookie_file(self):
        file_path = self.open_file()
        if not file_path:
            return False
        try:
            with open(file_path, "r") as f:
                lines = f.readlines()
            self.cookies = []
            self.accounts = []
            for line in lines:
                parts = line.strip().split(":")
                if len(parts) == 3:
                    user, pwd, cookie = parts
                    self.cookies.append(cookie)
                    self.accounts.append(user)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")
            return False

    def inject_cookies(self):
        self.text_area.delete('1.0', tk.END)
        if not self.read_cookie_file():
            return
        for idx, cookie in enumerate(self.cookies):
            user = self.accounts[idx]
            self.text_area.insert(tk.END, f"Injecting cookie for {user}...\n")
            session = requests.Session()
            session.cookies['.ROBLOSECURITY'] = cookie
            r = session.get('https://users.roblox.com/v1/users/authenticated')
            if r.status_code == 200 and r.json().get("name"):
                roblox_user = r.json().get("name")
                self.text_area.insert(tk.END, f"[SUCCESS] Cookie injected for Roblox account: {roblox_user}\n")
            else:
                self.text_area.insert(tk.END, f"[FAILED] Cookie injection failed for {user}\n")
            self.text_area.insert(tk.END, "-"*50 + "\n")
        self.text_area.insert(tk.END, "Cookie injection completed.\n")

    def logout_all(self):
        self.text_area.delete('1.0', tk.END)
        if not self.read_cookie_file():
            return
        for idx, cookie in enumerate(self.cookies):
            user = self.accounts[idx]
            self.text_area.insert(tk.END, f"Logging out all devices for {user}...\n")
            session = requests.Session()
            session.cookies['.ROBLOSECURITY'] = cookie
            r = session.post("https://auth.roblox.com/v2/logout/from-all-devices")
            if r.status_code == 200:
                self.text_area.insert(tk.END, f"[SUCCESS] Logged out all devices for Roblox account: {user}\n")
            else:
                self.text_area.insert(tk.END, f"[FAILED] Logout failed for {user}\n")
            self.text_area.insert(tk.END, "-"*50 + "\n")
        self.text_area.insert(tk.END, "Logout all completed.\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = CookieInjectorApp(root)
    root.mainloop()