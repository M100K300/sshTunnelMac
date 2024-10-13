import subprocess
import threading
import tkinter as tk
from tkinter import messagebox
import json
import os
import urllib.parse

class SSHManager:
    def __init__(self):
        self.ssh_command_template = []
        self.process = None

    def set_socks_proxy(self):
        """Enable SOCKS proxy on Wi-Fi."""
        command = [
            "networksetup", "-setsocksfirewallproxy", "Wi-Fi", "127.0.0.1", "9443"
        ]
        subprocess.run(command)
        print("SOCKS proxy enabled on Wi-Fi.")

    def disable_socks_proxy(self):
        """Disable SOCKS proxy on Wi-Fi."""
        command = [
            "networksetup", "-setsocksfirewallproxystate", "Wi-Fi", "off"
        ]
        subprocess.run(command)
        print("SOCKS proxy disabled on Wi-Fi.")

    def terminate_ssh(self):
        """Terminate SSH connection if running."""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            print("SSH connection terminated.")

    def start_ssh(self, ip_address, username, password, port):
        """Start the SSH connection."""
        self.ssh_command_template = [
            "sshpass", "-p", password,  # Password provided via sshpass
            "ssh",
            "-o", "StrictHostKeyChecking=no",  # Avoid host key verification prompt
            "-N",                              # Do not execute any remote commands
            "-D9443",                          # Set up a local SOCKS proxy on port 9443
            f"{username}@{ip_address}", 
            f"-p {port}"
        ]
        try:
            self.process = subprocess.Popen(
                self.ssh_command_template,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            print(f"SSH connection started with {username}@{ip_address} on port {port}.")
        except Exception as e:
            print(f"Failed to start SSH connection: {e}")

class App:
    def __init__(self, root):
        self.settings_json = os.path.join(os.path.expanduser("~"), "ssh_preset.json")

        self.ssh_manager = SSHManager()
        self.root = root
        self.root.title("SSH Proxy Manager")

        # IP Address Input
        self.ip_label = tk.Label(root, text="IP Address:", font=("Helvetica", 12))
        self.ip_label.pack(pady=5)
        self.ip_entry = tk.Entry(root, font=("Helvetica", 12), width=30)
        self.ip_entry.pack(pady=5)

        # Username Input
        self.username_label = tk.Label(root, text="Username:", font=("Helvetica", 12))
        self.username_label.pack(pady=5)
        self.username_entry = tk.Entry(root, font=("Helvetica", 12), width=30)
        self.username_entry.insert(0, "root")
        self.username_entry.pack(pady=5)

        # Password Input
        self.password_label = tk.Label(root, text="Password:", font=("Helvetica", 12))
        self.password_label.pack(pady=5)
        self.password_entry = tk.Entry(root, show='*', font=("Helvetica", 12), width=30)
        self.password_entry.pack(pady=5)

        # Port Input
        self.port_label = tk.Label(root, text="Port:", font=("Helvetica", 12))
        self.port_label.pack(pady=5)
        self.port_entry = tk.Entry(root, font=("Helvetica", 12), width=30)
        self.port_entry.insert(0, "22")
        self.port_entry.pack(pady=5)

        # Status label
        self.status_label = tk.Label(root, text="Status: Not Connected", font=("Helvetica", 14))
        self.status_label.pack(pady=10)

        # Buttons
        self.start_button = tk.Button(root, text="Start Proxy", command=self.start_proxy, width=20)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Proxy", command=self.stop_proxy, width=20)
        self.stop_button.pack(pady=5)

        self.restart_button = tk.Button(root, text="Restart Proxy", command=self.restart_proxy, width=20)
        self.restart_button.pack(pady=5)

        self.save_button = tk.Button(root, text="Save Preset", command=self.save_preset, width=20)
        self.save_button.pack(pady=5)

        self.load_button = tk.Button(root, text="Load Preset", command=self.load_preset, width=20)
        self.load_button.pack(pady=5)

        self.exit_button = tk.Button(root, text="Exit", command=self.exit_program, width=20)
        self.exit_button.pack(pady=5)

        self.is_running = False

        self.load_preset(show_success_alert = False)

    def update_status(self, message):
        self.status_label.config(text=f"Status: {message}")

    def start_proxy(self):
        if not self.is_running:
            ip_address = self.ip_entry.get().strip()
            password = self.password_entry.get().strip()
            username = self.username_entry.get().strip()
            port = self.port_entry.get().strip()
            if not ip_address or not password:
                messagebox.showerror("Input Error", "Please enter both IP Address and Password.")
                return
            
            self.is_running = True
            self.update_status("Connecting...")
            threading.Thread(target=self._start_proxy, args=(ip_address, username, password, port)).start()

    def _start_proxy(self, ip_address, username, password, port):
        self.ssh_manager.start_ssh(ip_address, username, password, port)
        self.ssh_manager.set_socks_proxy()
        self.update_status("Proxy Running")

    def stop_proxy(self):
        if self.is_running:
            self.ssh_manager.disable_socks_proxy()
            self.ssh_manager.terminate_ssh()
            self.is_running = False
            self.update_status("Proxy Stopped")

    def restart_proxy(self):
        self.update_status("Restarting Proxy...")
        if self.is_running:
            self.stop_proxy()
        self.start_proxy()

    def save_preset(self):
        """Save SSH preset to a JSON file."""
        ip_address = self.ip_entry.get().strip()
        password = self.password_entry.get().strip()

        if not ip_address or not password:
            messagebox.showerror("Input Error", "Please enter both IP Address and Password.")
            return

        # URL-encode the password for the SSH URL
        encoded_password = urllib.parse.quote(password)
        preset = {
            "url": f"ssh://root:{encoded_password}@{ip_address}:22"
        }

        with open(self.settings_json, "w") as file:
            json.dump(preset, file)
            messagebox.showinfo("Success", "Preset saved successfully!")

    def load_preset(self, show_success_alert = True):
        """Load SSH preset from a JSON file."""
        if os.path.exists(self.settings_json):
            with open(self.settings_json, "r") as file:
                preset = json.load(file)
                url = preset.get("url", "")
                if url:
                    # Extract username, password, and IP address from URL
                    user_info, host_info = url.split("://")[1].split("@")
                    username, encoded_password = user_info.split(":")
                    ip_address = host_info.split(":")[0]

                    # Decode the password
                    password = urllib.parse.unquote(encoded_password)

                    self.ip_entry.delete(0, tk.END)
                    self.password_entry.delete(0, tk.END)
                    self.ip_entry.insert(0, ip_address)
                    self.password_entry.insert(0, password)
                    if show_success_alert:
                        messagebox.showinfo("Success", "Preset loaded successfully!")
                else:
                    messagebox.showerror("Load Error", "Preset data is invalid.")
        else:
            messagebox.showerror("File Error", "Preset file not found.")

    def exit_program(self):
        if self.is_running:
            self.stop_proxy()
        self.root.quit()

# Entry point
if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.exit_program)  # Handle window close
    root.mainloop()
