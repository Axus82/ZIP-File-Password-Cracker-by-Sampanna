import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import zipfile
import threading
import os

class ZipWordlistCracker:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("ZIP File Password Cracker (Wordlist Only)")
        self.window.geometry("600x400")

        # GUI Elements
        tk.Label(self.window, text="ZIP File Password Cracker (Wordlist Only)", font=("Arial", 14)).pack(pady=10)

        # ZIP file selection
        tk.Label(self.window, text="Select a password-protected ZIP file:", font=("Arial", 10)).pack()
        self.zip_path = tk.StringVar()
        tk.Button(self.window, text="Browse ZIP File", 
                 command=self.select_zip_file, 
                 font=("Arial", 10)).pack(pady=5)

        # Wordlist file selection (fixed to rockyou.txt or custom)
        tk.Label(self.window, text="Select rockyou.txt or custom wordlist:", font=("Arial", 10)).pack()
        self.wordlist_path = tk.StringVar(value="rockyou.txt")  # Default to rockyou.txt
        tk.Button(self.window, text="Browse Wordlist", 
                 command=self.select_wordlist, 
                 font=("Arial", 10)).pack(pady=5)

        # Output area
        self.output_text = scrolledtext.ScrolledText(self.window, width=70, height=20, font=("Arial", 10))
        self.output_text.pack(pady=10)

        # Start, Stop, and Quit buttons
        button_frame = tk.Frame(self.window)
        button_frame.pack(pady=5)

        self.stop_event = threading.Event()
        tk.Button(button_frame, text="Start Cracking", 
                 command=self.start_cracking, 
                 font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Stop Cracking", 
                 command=self.stop_cracking, 
                 font=("Arial", 10)).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Quit", 
                 command=self.window.quit, 
                 font=("Arial", 10)).pack(side=tk.LEFT, padx=5)

        self.cracking_thread = None

    def select_zip_file(self):
        """Open a file dialog to select the ZIP file."""
        zip_path = filedialog.askopenfilename(filetypes=[("ZIP files", "*.zip")])
        if zip_path:
            self.zip_path.set(zip_path)
            self.output_text.insert(tk.END, f"Selected ZIP file: {zip_path}\n")
            self.output_text.see(tk.END)

    def select_wordlist(self):
        """Open a file dialog to select the wordlist file (defaults to rockyou.txt)."""
        wordlist_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if wordlist_path:
            self.wordlist_path.set(wordlist_path)
            self.output_text.insert(tk.END, f"Selected wordlist: {wordlist_path}\n")
            self.output_text.see(tk.END)

    def crack_zip_password(self, zip_path, wordlist_path):
        """Attempt to crack the ZIP file password using only the wordlist."""
        if not zip_path or not os.path.exists(zip_path):
            self.output_text.insert(tk.END, "No valid ZIP file selected.\n")
            self.output_text.see(tk.END)
            return

        if not wordlist_path or not os.path.exists(wordlist_path):
            self.output_text.insert(tk.END, "No valid wordlist file selected.\n")
            self.output_text.see(tk.END)
            return

        self.output_text.insert(tk.END, f"Starting dictionary attack on {zip_path} using {wordlist_path}...\n")
        self.output_text.see(tk.END)

        found = False
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_file:
                for file_info in zip_file.infolist():
                    if file_info.flag_bits & 0x1:  # Check if password-protected
                        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as wordlist:
                            for line in wordlist:
                                guess = line.strip()
                                if not guess or self.stop_event.is_set():
                                    continue
                                
                                self.output_text.insert(tk.END, f"Trying: {guess}\n")
                                self.output_text.see(tk.END)
                                self.window.update()

                                try:
                                    zip_file.read(file_info.filename, pwd=guess.encode('utf-8'))
                                    found = True
                                    self.output_text.insert(tk.END, f"Password found: {guess}!\n")
                                    self.output_text.see(tk.END)
                                    messagebox.showinfo("Success", f"ZIP password cracked: {guess}")
                                    return
                                except RuntimeError:
                                    continue

        except Exception as e:
            self.output_text.insert(tk.END, f"Error: {str(e)}\n")
            self.output_text.see(tk.END)
            messagebox.showerror("Error", f"Failed to crack ZIP: {e}")

        if not found:
            self.output_text.insert(tk.END, "Password not found in the wordlist.\n")
            self.output_text.see(tk.END)
            messagebox.showwarning("Failure", "Could not crack the ZIP password with the wordlist.")

    def start_cracking(self):
        """Start the dictionary attack in a separate thread."""
        if self.cracking_thread and self.cracking_thread.is_alive():
            messagebox.showwarning("Warning", "Cracking is already in progress!")
            return

        zip_path = self.zip_path.get().strip()
        wordlist_path = self.wordlist_path.get().strip()
        if not zip_path or not wordlist_path:
            messagebox.showerror("Error", "Please select both a ZIP file and wordlist.")
            return

        self.stop_event.clear()
        self.output_text.delete(1.0, tk.END)
        self.cracking_thread = threading.Thread(target=self.crack_zip_password, 
                                               args=(zip_path, wordlist_path), 
                                               daemon=True)
        self.cracking_thread.start()

    def stop_cracking(self):
        """Stop the dictionary attack."""
        self.stop_event.set()
        self.output_text.insert(tk.END, "Stopping dictionary attack...\n")
        self.output_text.see(tk.END)

    def run(self):
        """Run the GUI main loop.""" 
        self.window.mainloop()

if __name__ == "__main__":
    cracker = ZipWordlistCracker()
    cracker.run()
