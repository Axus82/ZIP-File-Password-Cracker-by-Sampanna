import hashlib
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

def calculate_file_hash(filename):
    """Calculate MD5 hash of a file."""
    hash_md5 = hashlib.md5()
    try:
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except FileNotFoundError:
        return None
    except Exception as e:
        return f"Error reading file {filename}: {e}"

def save_hash(filename, hash_value):
    """Save the hash value to a text file."""
    hash_filename = f"{filename}.hash"
    with open(hash_filename, "w") as f:
        f.write(hash_value)
    return hash_filename

def check_hash(filename, output_text):
    """Check if the current file hash matches the saved hash."""
    hash_filename = f"{filename}.hash"
    
    # Calculate current hash
    current_hash = calculate_file_hash(filename)
    if current_hash is None:
        output_text.insert(tk.END, f"Could not calculate hash for {filename}\n")
        return
    elif isinstance(current_hash, str) and current_hash.startswith("Error"):
        output_text.insert(tk.END, f"{current_hash}\n")
        return
    
    # Check if hash file exists
    if not os.path.exists(hash_filename):
        hash_file = save_hash(filename, current_hash)
        output_text.insert(tk.END, f"No previous hash found. Hash saved to {hash_file}\n")
        return
    
    # Read saved hash
    with open(hash_filename, "r") as f:
        saved_hash = f.read().strip()
    
    # Compare hashes
    if current_hash == saved_hash:
        output_text.insert(tk.END, f"File integrity verified: {filename} has not been modified.\n")
    else:
        output_text.insert(tk.END, f"WARNING: File integrity compromised! {filename} has been modified.\n")
        output_text.insert(tk.END, f"Original hash: {saved_hash}\n")
        output_text.insert(tk.END, f"Current hash:  {current_hash}\n")

def select_file(output_text):
    """Open file dialog and check the selected file."""
    filename = filedialog.askopenfilename(title="Select a file to check")
    if filename:
        output_text.delete(1.0, tk.END)  # Clear previous output
        output_text.insert(tk.END, f"Checking file: {filename}\n")
        check_hash(filename, output_text)

def create_gui():
    """Create an attractive GUI window."""
    # Create the main window with a custom background
    window = tk.Tk()
    window.title("File Integrity Checker")
    window.geometry("600x400")
    window.configure(bg="#f0f8ff")  # Light blue background for a clean look

    # Create a gradient-like effect using frames
    top_frame = tk.Frame(window, bg="#87ceeb", height=50)  # Sky blue header
    top_frame.pack(fill="x")

    # Title label with styling
    title_label = tk.Label(top_frame, text="File Integrity Checker", font=("Helvetica", 16, "bold"), 
                          bg="#87ceeb", fg="white", pady=10)
    title_label.pack()

    # Main content frame with a slightly different background
    main_frame = tk.Frame(window, bg="#e6f3ff")  # Light pastel blue
    main_frame.pack(fill="both", expand=True, padx=10, pady=10)

    # Label for instructions
    label = tk.Label(main_frame, text="Select a file to check its integrity", font=("Arial", 12), 
                     bg="#e6f3ff", fg="#333333")
    label.pack(pady=10)

    # Styled button to select file
    select_button = tk.Button(main_frame, text="Select File", command=lambda: select_file(output_text), 
                             font=("Arial", 10, "bold"), bg="#4CAF50", fg="white", 
                             padx=10, pady=5, relief="raised", cursor="hand2")
    select_button.pack(pady=5)

    # Output area (scrollable text) with styled background
    output_text = scrolledtext.ScrolledText(main_frame, width=70, height=20, font=("Arial", 10), 
                                          bg="#ffffff", fg="#000000", relief="sunken", bd=2)
    output_text.pack(pady=10)

    # Styled quit button
    quit_button = tk.Button(main_frame, text="Quit", command=window.quit, 
                           font=("Arial", 10, "bold"), bg="#f44336", fg="white", 
                           padx=10, pady=5, relief="raised", cursor="hand2")
    quit_button.pack(pady=5)

    # Optional: Add an icon (if you have an .ico or .png file)
    try:
        # Replace 'icon.ico' with your icon file path (e.g., 'D:/path/to/icon.ico')
        window.iconbitmap('icon.ico')  # Windows .ico file
    except tk.TclError:
        print("Icon not found. Using default window icon.")

    window.mainloop()

if __name__ == "__main__":
    create_gui()