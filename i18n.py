# i18n.py — Internationalization module for ProtocolHarbor
# Supported languages: "pl" (Polish), "en" (English)
# Auto-detects OS locale on first import; call set_language() to override.

import locale
import tkinter as tk

_current_lang: str = "en"

# ── Flag images (16×11 px, Base64 PNG) ────────────────────────────────────────
# Polish flag: white/red horizontal stripes
_FLAG_PL_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAABAAAAALCAYAAAB24g05AAAABmJLR0QA/wD/"
    "AP+gvaeTAAAADUlEQVQoz2P4z8BQDwAEgAF/QualIQAAAABJRU5ErkJggg=="
)
# UK flag: Union Jack
_FLAG_EN_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAABAAAAALCAYAAAB24g05AAAABmJLR0QA/wD/"
    "AP+gvaeTAAAADUlEQVQoz2NgYGD4DwABBAEAWB9NngAAAABJRU5ErkJggg=="
)

# We generate proper pixel-art flags programmatically (no external file needed)
def _make_flag_pl(size=(22, 14)) -> "tk.PhotoImage":
    """Polish flag: top half white, bottom half red."""
    w, h = size
    img = tk.PhotoImage(width=w, height=h)
    half = h // 2
    img.put("white", to=(0, 0, w, half))
    img.put("#dc143c", to=(0, half, w, h))
    # thin grey border
    for x in range(w):
        img.put("#999999", to=(x, 0, x+1, 1))
        img.put("#999999", to=(x, h-1, x+1, h))
    for y in range(h):
        img.put("#999999", to=(0, y, 1, y+1))
        img.put("#999999", to=(w-1, y, w, y+1))
    return img

def _make_flag_en(size=(22, 14)) -> "tk.PhotoImage":
    """UK flag: simplified Union Jack (red cross on blue)."""
    w, h = size
    img = tk.PhotoImage(width=w, height=h)
    # blue background
    img.put("#012169", to=(0, 0, w, h))
    # white diagonals
    for i in range(max(w, h)):
        x1 = int(i * w / max(w, h))
        y1 = int(i * h / max(w, h))
        for t in range(-1, 2):
            if 0 <= x1+t < w and 0 <= y1 < h:
                img.put("white", to=(x1+t, y1, x1+t+1, y1+1))
            x2 = w - 1 - x1
            if 0 <= x2+t < w and 0 <= y1 < h:
                img.put("white", to=(x2+t, y1, x2+t+1, y1+1))
    # white cross
    cx, cy = w // 2, h // 2
    img.put("white", to=(0, cy-2, w, cy+2))
    img.put("white", to=(cx-2, 0, cx+2, h))
    # red cross (thinner)
    img.put("#c8102e", to=(0, cy-1, w, cy+1))
    img.put("#c8102e", to=(cx-1, 0, cx+1, h))
    # border
    for x in range(w):
        img.put("#000033", to=(x, 0, x+1, 1))
        img.put("#000033", to=(x, h-1, x+1, h))
    for y in range(h):
        img.put("#000033", to=(0, y, 1, y+1))
        img.put("#000033", to=(w-1, y, w, y+1))
    return img


# ── Translation dictionary ─────────────────────────────────────────────────────
# Keys are the Polish (canonical) strings used throughout gui.py.
# Values are their English equivalents.
# fmt: off
_TRANSLATIONS: dict[str, dict[str, str]] = {
    # ── Top bar ──────────────────────────────────────────────
    "Adapter sieciowy":         {"en": "Network adapter",         "pl": "Adapter sieciowy"},
    "Skanuj:":                  {"en": "Scan:",                   "pl": "Skanuj:"},
    "Wszystkie adaptery":       {"en": "All adapters",            "pl": "Wszystkie adaptery"},
    "▶  Skanuj":                {"en": "▶  Scan",                 "pl": "▶  Skanuj"},
    "⏹  Zatrzymaj":             {"en": "⏹  Stop",                 "pl": "⏹  Zatrzymaj"},
    "🗑  Wyczyść":               {"en": "🗑  Clear",               "pl": "🗑  Wyczyść"},
    "Gotowy":                   {"en": "Ready",                   "pl": "Gotowy"},
    # ── Table ────────────────────────────────────────────────
    "Znalezione urządzenia":    {"en": "Discovered devices",      "pl": "Znalezione urządzenia"},
    "Filtr producenta:":        {"en": "Vendor filter:",          "pl": "Filtr producenta:"},
    "Wszyscy producenci":       {"en": "All vendors",             "pl": "Wszyscy producenci"},
    "Legenda:":                 {"en": "Legend:",                 "pl": "Legenda:"},
    "IP karty sieciowej":       {"en": "Adapter IP",              "pl": "IP karty sieciowej"},
    "Ta sama podsieć  ":        {"en": "Same subnet  ",           "pl": "Ta sama podsieć  "},
    "Inna podsieć  ":           {"en": "Different subnet  ",      "pl": "Inna podsieć  "},
    "Konflikt IP":              {"en": "IP conflict",             "pl": "Konflikt IP"},
    "Adres IP":                 {"en": "IP Address",              "pl": "Adres IP"},
    "Adres MAC":                {"en": "MAC Address",             "pl": "Adres MAC"},
    "Producent":                {"en": "Vendor",                  "pl": "Producent"},
    "Nazwa modułu":             {"en": "Module name",             "pl": "Nazwa modułu"},
    "Opis urządzenia":          {"en": "Device description",      "pl": "Opis urządzenia"},
    "Protokół":                 {"en": "Protocol",                "pl": "Protokół"},
    "ID producenta":            {"en": "Vendor ID",               "pl": "ID producenta"},
    "ID urządzenia":            {"en": "Device ID",               "pl": "ID urządzenia"},
    "Wersja":                   {"en": "Version",                 "pl": "Wersja"},
    "Adapter":                  {"en": "Adapter",                 "pl": "Adapter"},
    # ── Bottom bar ───────────────────────────────────────────
    "zmiany":                   {"en": "changelog",               "pl": "zmiany"},
    "github: ProtocolHarbor":   {"en": "github: ProtocolHarbor",  "pl": "github: ProtocolHarbor"},
    "Changelog":                {"en": "Changelog",               "pl": "Changelog"},
    "Log":                      {"en": "Log",                     "pl": "Log"},
    # ── Status / log messages ────────────────────────────────
    "Wybrano adapter:":                     {"en": "Adapter selected:",                 "pl": "Wybrano adapter:"},
    "Filtr producenta:":                    {"en": "Vendor filter:",                    "pl": "Filtr producenta:"},
    "Wykryto urządzenie:":                  {"en": "Device discovered:",                "pl": "Wykryto urządzenie:"},
    "Wykryto urządzenie Profinet DCP:":     {"en": "Profinet DCP device discovered:",   "pl": "Wykryto urządzenie Profinet DCP:"},
    "Wykryto urządzenie EtherCAT:":         {"en": "EtherCAT device discovered:",       "pl": "Wykryto urządzenie EtherCAT:"},
    "Wykryto urządzenie EtherNet/IP:":      {"en": "EtherNet/IP device discovered:",    "pl": "Wykryto urządzenie EtherNet/IP:"},
    "Wykryto urządzenie Modbus TCP:":       {"en": "Modbus TCP device discovered:",     "pl": "Wykryto urządzenie Modbus TCP:"},
    "Uzupełniono dane przez LLDP:":         {"en": "Data enriched via LLDP:",           "pl": "Uzupełniono dane przez LLDP:"},
    "⏳ Skanowanie w toku…":                {"en": "⏳ Scanning…",                      "pl": "⏳ Skanowanie w toku…"},
    "Zatrzymano.":                          {"en": "Stopped.",                          "pl": "Zatrzymano."},
    "Skan zatrzymany.":                     {"en": "Scan stopped.",                     "pl": "Skan zatrzymany."},
    "Wyniki wyczyszczone.":                 {"en": "Results cleared.",                  "pl": "Wyniki wyczyszczone."},
    "Otwieram panel urządzenia: http://":   {"en": "Opening device web panel: http://", "pl": "Otwieram panel urządzenia: http://"},
    "[UWAGA] Konflikt IP w ARP (":          {"en": "[WARNING] IP conflict in ARP (",    "pl": "[UWAGA] Konflikt IP w ARP ("},
    "— wiele MAC:":                         {"en": "— multiple MACs:",                  "pl": "— wiele MAC:"},
    "(rozpłączono scalony wpis)":           {"en": "(merged entry split)",              "pl": "(rozpłączono scalony wpis)"},
    "brak IP":                              {"en": "no IP",                             "pl": "brak IP"},
    "Start skanowania ARP + Profinet DCP + EtherCAT oraz identyfikacji EtherNet/IP i Modbus TCP na wszystkich adapterach…":
        {"en": "Starting ARP + Profinet DCP + EtherCAT scan with EtherNet/IP and Modbus TCP identification on all adapters…",
         "pl": "Start skanowania ARP + Profinet DCP + EtherCAT oraz identyfikacji EtherNet/IP i Modbus TCP na wszystkich adapterach…"},
    "Start skanowania ARP + Profinet DCP + EtherCAT oraz identyfikacji EtherNet/IP i Modbus TCP na:":
        {"en": "Starting ARP + Profinet DCP + EtherCAT scan with EtherNet/IP and Modbus TCP identification on:",
         "pl": "Start skanowania ARP + Profinet DCP + EtherCAT oraz identyfikacji EtherNet/IP i Modbus TCP na:"},
    # ── Balluff switch dialog ────────────────────────────────
    "Przełączenie protokołu Balluff BNI XG": {"en": "Balluff BNI XG Protocol Switch",    "pl": "Przełączenie protokołu Balluff BNI XG"},
    "Przełączenie interfejsu":               {"en": "Interface switch",                  "pl": "Przełączenie interfejsu"},
    "Moduł:":                                {"en": "Module:",                           "pl": "Moduł:"},
    "Vendor ID:":                            {"en": "Vendor ID:",                        "pl": "Vendor ID:"},
    "Slave index:":                          {"en": "Slave index:",                      "pl": "Slave index:"},
    "Adapter:":                              {"en": "Adapter:",                          "pl": "Adapter:"},
    "Docelowy protokół:":                    {"en": "Target protocol:",                  "pl": "Docelowy protokół:"},
    "Ethernet IP":                           {"en": "Ethernet IP",                       "pl": "Ethernet IP"},
    "Profinet DCP":                          {"en": "Profinet DCP",                      "pl": "Profinet DCP"},
    "Modbus TCP":                            {"en": "Modbus TCP",                        "pl": "Modbus TCP"},
    "Akcja wyśle sekwencję CoE SDO (set + reboot): 0xF502:02, 0xF503:01, 0xF503:02.":
        {"en": "Action will send CoE SDO sequence (set + reboot): 0xF502:02, 0xF503:01, 0xF503:02.",
         "pl": "Akcja wyśle sekwencję CoE SDO (set + reboot): 0xF502:02, 0xF503:01, 0xF503:02."},
    "Wysyłanie sekwencji…":                  {"en": "Sending sequence…",                 "pl": "Wysyłanie sekwencji…"},
    "[EtherCAT] Zatrzymano skan przed przełączeniem interfejsu.":
        {"en": "[EtherCAT] Scan stopped before interface switch.",
         "pl": "[EtherCAT] Zatrzymano skan przed przełączeniem interfejsu."},
    ". Zrób ponowny skan, aby sprawdzić efekt.":
        {"en": ". Run a new scan to verify the result.",
         "pl": ". Zrób ponowny skan, aby sprawdzić efekt."},
    "[EtherCAT] Wysłano przełączenie do":    {"en": "[EtherCAT] Switch sent to",         "pl": "[EtherCAT] Wysłano przełączenie do"},
    "[EtherCAT] Błąd przełączenia do":       {"en": "[EtherCAT] Switch error to",        "pl": "[EtherCAT] Błąd przełączenia do"},
    "Przełącz":                              {"en": "Switch",                            "pl": "Przełącz"},
    "Zamknij":                               {"en": "Close",                             "pl": "Zamknij"},
    # ── Profinet config dialog ───────────────────────────────
    "Konfiguracja Profinet DCP":             {"en": "Profinet DCP Configuration",        "pl": "Konfiguracja Profinet DCP"},
    "Urządzenie":                            {"en": "Device",                            "pl": "Urządzenie"},
    "Adres MAC:":                            {"en": "MAC Address:",                      "pl": "Adres MAC:"},
    "Aktualny IP:":                          {"en": "Current IP:",                       "pl": "Aktualny IP:"},
    "Nazwa stacji:":                         {"en": "Station name:",                     "pl": "Nazwa stacji:"},
    "Zmień adres IP":                        {"en": "Change IP address",                 "pl": "Zmień adres IP"},
    "Nowy adres IP:":                        {"en": "New IP address:",                   "pl": "Nowy adres IP:"},
    "Maska podsieci:":                       {"en": "Subnet mask:",                      "pl": "Maska podsieci:"},
    "Brama domyślna:":                       {"en": "Default gateway:",                  "pl": "Brama domyślna:"},
    "Zapisz trwale (permanent)":             {"en": "Save permanently",                  "pl": "Zapisz trwale (permanent)"},
    "⚠ Nie udało się zweryfikować (brak odpowiedzi Identify).":
        {"en": "⚠ Verification failed (no Identify response).",
         "pl": "⚠ Nie udało się zweryfikować (brak odpowiedzi Identify)."},
    "✓ IP zmieniony na":                     {"en": "✓ IP changed to",                   "pl": "✓ IP zmieniony na"},
    "OK":                                    {"en": "OK",                                "pl": "OK"},
    "(oczekiwano":                           {"en": "(expected",                         "pl": "(oczekiwano"},
    "). Zmiana nieutrzymana (możliwe nadpisanie przez controller lub logikę urządzenia).":
        {"en": "). Change not retained (possibly overwritten by controller or device logic).",
         "pl": "). Zmiana nieutrzymana (możliwe nadpisanie przez controller lub logikę urządzenia)."},
    "⚠ Weryfikacja: po chwili IP=":          {"en": "⚠ Verification: IP after delay=",  "pl": "⚠ Weryfikacja: po chwili IP="},
    "). SET nie został skutecznie potwierdzony przez urządzenie.":
        {"en": "). SET was not confirmed by the device.",
         "pl": "). SET nie został skutecznie potwierdzony przez urządzenie."},
    "⚠ Weryfikacja: IP pozostał":            {"en": "⚠ Verification: IP remained",       "pl": "⚠ Weryfikacja: IP pozostał"},
    "[Profinet] Weryfikacja: IP urządzenia": {"en": "[Profinet] Verification: device IP", "pl": "[Profinet] Weryfikacja: IP urządzenia"},
    "niezgodny (":                           {"en": "mismatch (",                        "pl": "niezgodny ("},
    "✓ Nazwa zmieniona na '":                {"en": "✓ Name changed to '",               "pl": "✓ Nazwa zmieniona na '"},
    "⚠ Weryfikacja: po chwili nazwa='":      {"en": "⚠ Verification: name after delay='","pl": "⚠ Weryfikacja: po chwili nazwa='"},
    "' (oczekiwano '":                       {"en": "' (expected '",                     "pl": "' (oczekiwano '"},
    "'). Zmiana nieutrzymana.":              {"en": "'). Change not retained.",           "pl": "'). Zmiana nieutrzymana."},
    "⚠ Weryfikacja: nazwa pozostała '":      {"en": "⚠ Verification: name remained '",   "pl": "⚠ Weryfikacja: nazwa pozostała '"},
    "'). SET nie został skutecznie potwierdzony.":
        {"en": "'). SET was not confirmed.",
         "pl": "'). SET nie został skutecznie potwierdzony."},
    "[Profinet] Weryfikacja: nazwa stacji":  {"en": "[Profinet] Verification: station name", "pl": "[Profinet] Weryfikacja: nazwa stacji"},
    "niezgodna ('":                          {"en": "mismatch ('",                       "pl": "niezgodna ('"},
    "Wysyłanie…":                            {"en": "Sending…",                          "pl": "Wysyłanie…"},
    "✓ Zmiana wysłana (":                    {"en": "✓ Change sent (",                   "pl": "✓ Zmiana wysłana ("},
    "[Profinet] IP urządzenia":              {"en": "[Profinet] Device IP",              "pl": "[Profinet] IP urządzenia"},
    "Ustaw IP":                              {"en": "Set IP",                            "pl": "Ustaw IP"},
    "Zmień nazwę stacji Profinet":           {"en": "Change Profinet station name",      "pl": "Zmień nazwę stacji Profinet"},
    "Nowa nazwa:":                           {"en": "New name:",                         "pl": "Nowa nazwa:"},
    "(a–z, 0–9, myślnik, kropka; maks. 240 znaków)":
        {"en": "(a–z, 0–9, hyphen, dot; max 240 chars)",
         "pl": "(a–z, 0–9, myślnik, kropka; maks. 240 znaków)"},
    "[Profinet] Nazwa stacji":               {"en": "[Profinet] Station name",           "pl": "[Profinet] Nazwa stacji"},
    "Ustaw nazwę":                           {"en": "Set name",                          "pl": "Ustaw nazwę"},
    # ── EtherCAT diagnostics ─────────────────────────────────
    "--- Diagnostyka EtherCAT ---":          {"en": "--- EtherCAT Diagnostics ---",      "pl": "--- Diagnostyka EtherCAT ---"},
    # ── Language switcher ────────────────────────────────────
    "Język:":                                {"en": "Language:",                         "pl": "Język:"},
}
# fmt: on


def _detect_os_language() -> str:
    """Return 'pl' if OS locale is Polish, otherwise 'en'."""
    try:
        lang, _ = locale.getlocale()
        if lang and lang.lower().startswith("pl"):
            return "pl"
    except Exception:
        pass
    try:
        import ctypes
        lcid = ctypes.windll.kernel32.GetUserDefaultUILanguage()
        # 0x0415 = Polish
        if (lcid & 0xFF) == 0x15:
            return "pl"
    except Exception:
        pass
    return "en"


def init_language() -> None:
    """Detect OS language and set it as current. Call once at startup."""
    global _current_lang
    _current_lang = _detect_os_language()


def set_language(lang: str) -> None:
    """Explicitly set language ('pl' or 'en')."""
    global _current_lang
    if lang in ("pl", "en"):
        _current_lang = lang


def get_language() -> str:
    return _current_lang


def t(key: str) -> str:
    """Translate *key* to the current language. Falls back to key itself."""
    entry = _TRANSLATIONS.get(key)
    if entry is None:
        return key
    return entry.get(_current_lang, key)


# ── Changelog (bilingual) ──────────────────────────────────────────────────────
_CHANGELOG_EN = """\
Changelog

[1.2.0]

- Added IP status dot column with color legend (blue = own NIC, green = same subnet, yellow = other subnet, red = conflict).
- Double-click on green IP opens device web panel in browser.
- Selecting a different adapter clears the results table.
- Added GUI action for Balluff BNI XG: switch EtherCAT → EtherNet/IP via CoE SDO sequence.
- Fixed CoE switch sequence reliability (8-bit writes, target validation, mailbox serialization).

[1.1.0]

- Added Profinet DCP device configuration from GUI (gear action per Profinet row): set IP address and station name.
- Added post-save verification flow (Identify) to confirm whether IP/name persisted on device.
- Fixed DCP Set frame format compatibility (FrameID 0xFEFD) to match standard tooling behavior.
- Fixed DCP raw send source MAC handling on Windows/Npcap (use real adapter MAC instead of 00:00:00:00:00:00).
- Improved DCP response handling for VLAN-tagged PN-DCP frames.
- Improved verification messaging to avoid false "controller overwrite" conclusions when not confirmed.
- Moved Profinet gear column to first table column and adjusted column sizing priorities to fit window width without horizontal scrolling.
- Removed screenshot.png from repository.

[1.0.1]

- Added device description column in the main table for protocol-specific metadata (for example Profinet type of station).
- Added RFC 5227 style ARP conflict detection based on packet evidence (same IP seen with multiple MAC addresses).
- Added row highlighting rules:
\t- red for duplicate/conflicting IPs,
\t- light green for devices in the same subnet as the selected adapter,
\t- light yellow for devices outside the adapter subnet.
- Added producer fallback from MAC OUI using the bundled IEEE vendor database (Scapy manuf data).
- Extended Profinet DCP parsing to extract additional optional metadata including device family and firmware where available.
- Fixed subnet coloring stability on Windows by hardening ipconfig parsing and adding caching.

[1.0.0]

- Vendor-agnostic branding and documentation
- Unified device list: one row per physical device (except EtherCAT)
- Dynamic protocol switching in-place (ARP/Profinet/EtherNet-IP/Modbus)
- Protocol identity probing for EtherNet/IP and Modbus TCP
- LLDP enrichment for firmware and supplemental metadata
- Improved Profinet DCP parsing and field mapping
- Improved logging controls with module-scoped debug

[0.3.0]

- Added EtherCAT scan support

[0.2.0]

- Improved scan stability and adapter handling
- Improved Profinet DCP discovery in all-adapter mode
- Added GUI quality-of-life improvements

[0.1.0]

- Initial release
"""

_CHANGELOG_PL = """\
Changelog

[1.2.0]

- Dodano kolumnę z kolorową kropką statusu IP (niebieski = własna karta sieciowa, zielony = ta sama podsieć, żółty = inna podsieć, czerwony = konflikt).
- Dwuklik na zielonym IP otwiera webpanel urządzenia w przeglądarce.
- Wybór innego adaptera czyści tabelę wyników.
- Dodano akcję GUI dla Balluff BNI XG: przełączenie EtherCAT → EtherNet/IP przez sekwencję CoE SDO.
- Poprawiono niezawodność sekwencji przełączenia CoE (8-bitowe zapisy, walidacja targetu, serializacja skrzynek mailbox).

[1.1.0]

- Dodano konfigurację urządzeń Profinet DCP z GUI (akcja przycisku SET przy wierszu Profinet): ustawianie adresu IP i nazwy stacji.
- Dodano mechanizm weryfikacji po zapisie (Identify) potwierdzający czy IP/nazwa zostały zachowane w urządzeniu.
- Poprawiono kompatybilność formatu ramki DCP Set (FrameID 0xFEFD) zgodnie ze standardowym zachowaniem narzędzi.
- Poprawiono obsługę źródłowego MAC przy wysyłaniu surowych ramek DCP na Windows/Npcap (zamiast 00:00:00:00:00:00 używany jest rzeczywisty MAC adaptera).
- Poprawiono obsługę odpowiedzi DCP dla ramek PN-DCP ze znacznikiem VLAN.
- Poprawiono komunikaty weryfikacji, aby unikać fałszywych wniosków o "nadpisaniu przez controller" gdy nie zostało to potwierdzone.
- Przeniesiono kolumnę SET Profinet na pierwszą pozycję w tabeli; dostosowano priorytety szerokości kolumn tak, aby zmieściły się w oknie bez poziomego przewijania.
- Usunięto plik screenshot.png z repozytorium.

[1.0.1]

- Dodano kolumnę z opisem urządzenia w głównej tabeli (metadane właściwe dla protokołu, np. typ stacji Profinet).
- Dodano detekcję konfliktów IP w stylu RFC 5227 na podstawie dowodów z pakietów (ten sam IP widziany z wieloma adresami MAC).
- Dodano reguły podświetlania wierszy:
\t- czerwony dla zduplikowanych/konfliktujących IP,
\t- jasnozielony dla urządzeń w tej samej podsieci co wybrany adapter,
\t- jasnożółty dla urządzeń spoza podsieci adaptera.
- Dodano zapasowe rozpoznawanie producenta z OUI MAC przy użyciu dołączonej bazy danych dostawców IEEE (dane Scapy manuf).
- Rozszerzono parsowanie Profinet DCP o dodatkowe opcjonalne metadane, w tym rodzinę urządzenia i firmware (gdzie dostępne).
- Poprawiono stabilność kolorowania podsieci na Windows przez wzmocnienie parsowania ipconfig i dodanie cachowania.

[1.0.0]

- Neutralna dla producenta identyfikacja wizualna i dokumentacja
- Ujednolicona lista urządzeń: jeden wiersz na urządzenie fizyczne (z wyjątkiem EtherCAT)
- Dynamiczne przełączanie protokołów w miejscu (ARP/Profinet/EtherNet-IP/Modbus)
- Sondowanie tożsamości protokołu dla EtherNet/IP i Modbus TCP
- Wzbogacanie danych przez LLDP (firmware i dodatkowe metadane)
- Ulepszone parsowanie i mapowanie pól Profinet DCP
- Ulepszone logi z debugiem w zakresie modułu

[0.3.0]

- Dodano obsługę skanowania EtherCAT

[0.2.0]

- Poprawiono stabilność skanowania i obsługę adapterów
- Poprawiono wykrywanie Profinet DCP w trybie wszystkich adapterów
- Poprawiono jakość interfejsu graficznego

[0.1.0]

- Pierwsze wydanie
"""


def get_changelog(lang: str | None = None) -> str:
    """Return changelog text for the given language (or current language)."""
    if lang is None:
        lang = _current_lang
    return _CHANGELOG_PL if lang == "pl" else _CHANGELOG_EN
