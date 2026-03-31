# main.py
import sys
import os
import ctypes
import tkinter as tk
from debug_utils import configure_debug_logging, install_exception_hooks
from gui import App


WINDOWS_APP_ID = "marjac6.ProtocolHarbor"
_ICON_HANDLES = []

def _resource_path(filename):
    base = sys._MEIPASS if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.join(base, filename)


def _set_window_icon(root):
    icon_path = _resource_path("icon.ico")
    if not os.path.exists(icon_path):
        return

    try:
        root.iconbitmap(default=icon_path)
    except Exception:
        pass

    if os.name != "nt":
        return

    try:
        user32 = ctypes.windll.user32
        root.update_idletasks()
        hwnd = root.winfo_id()
        parent_hwnd = user32.GetParent(hwnd)
        if parent_hwnd:
            hwnd = parent_hwnd

        WM_SETICON = 0x0080
        ICON_BIG = 1
        ICON_SMALL = 0
        IMAGE_ICON = 1
        LR_LOADFROMFILE = 0x0010
        GCLP_HICON = -14
        GCLP_HICONSM = -34
        SM_CXICON = 11
        SM_CYICON = 12
        SM_CXSMICON = 49
        SM_CYSMICON = 50

        set_class_long = getattr(user32, "SetClassLongPtrW", None)
        if set_class_long is None:
            set_class_long = user32.SetClassLongW

        hbig = user32.LoadImageW(
            0,
            icon_path,
            IMAGE_ICON,
            user32.GetSystemMetrics(SM_CXICON),
            user32.GetSystemMetrics(SM_CYICON),
            LR_LOADFROMFILE,
        )
        hsmall = user32.LoadImageW(
            0,
            icon_path,
            IMAGE_ICON,
            user32.GetSystemMetrics(SM_CXSMICON),
            user32.GetSystemMetrics(SM_CYSMICON),
            LR_LOADFROMFILE,
        )

        if hbig:
            _ICON_HANDLES.append(hbig)
            user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, hbig)
            set_class_long(hwnd, GCLP_HICON, hbig)

        if hsmall:
            _ICON_HANDLES.append(hsmall)
            user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, hsmall)
            set_class_long(hwnd, GCLP_HICONSM, hsmall)
    except Exception:
        pass

if __name__ == "__main__":
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(WINDOWS_APP_ID)
    except Exception:
        pass
    configure_debug_logging()
    install_exception_hooks()
    root = tk.Tk()
    app = App(root)
    _set_window_icon(root)
    root.after_idle(lambda: _set_window_icon(root))
    root.mainloop()
