# main.py
import sys
import os
import tkinter as tk
from gui import App

def _resource_path(filename):
    base = sys._MEIPASS if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.join(base, filename)

if __name__ == "__main__":
    root = tk.Tk()
    try:
        root.iconbitmap(_resource_path("icon.ico"))
    except Exception:
        pass
    app = App(root)
    root.mainloop()
