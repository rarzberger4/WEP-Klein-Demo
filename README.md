# WEP Klein Demo

Ein Lehr- und Demo-Werkzeug, das den statistischen WEP-Angriff (Kleins Angriff)
als sichtbares **„Byte-Rennen"** darstellt.

Statt wie `aircrack-ng` den Schlüssel in Sekundenbruchteilen auszugeben, macht dieses
Tool den Vorgang **nachvollziehbar**: Man sieht, wie pro Schlüssel-Byte Stimmen
gesammelt werden und sich der richtige Wert langsam gegen das Rauschen durchsetzt.

> ⚠️ **Rechtlicher & ethischer Rahmen**
> Dieses Tool ist ausschließlich für den Einsatz am **eigenen** Access Point in einem
> **isolierten Testnetz** gedacht (Ausbildung/Demonstration).
> Der Autor übernimmt keine Haftung für missbräuchliche Verwendung.

---

## Was es zeigt

- **Phase 1 — Capture:** Mitschneiden der Initialisierungsvektoren (IVs) eines
  WEP-Netzes, optional mit **ARP-Replay-Injection**, um in Minuten statt Stunden
  genug IVs zu sammeln.
- **Phase 2 — Crack (das Byte-Rennen):** Aus den gesammelten Paketen wird der
  Schlüssel **live berechnet** und als wachsende Vote-Tabelle pro Byte animiert.
  Die ersten vier geheimen Bytes fallen statistisch (Klein), das letzte wird
  sichtbar per Brute-Force gegen den bekannten Klartext bestätigt.
- **Aufdeckung:** Der gefundene 64-bit-Schlüssel rastet am Ende grün ein.

Zusätzlich enthalten:

- **Backup-Modus:** Eine vorhandene `.cap`-Datei einlesen und offline knacken.
- Automatisches Sichern verifizierter Captures nach `~/wep_captures/`.

---

## Funktionsweise (kurz)

WEP verwendet die Stromchiffre RC4 mit einem **24-bit-IV**, das offen pro Paket
mitgesendet wird. Jedes WEP-Datenpaket beginnt mit dem festen LLC/SNAP-Header
`AA AA 03 00 00 00`, wodurch der Angreifer die ersten Keystream-Bytes kennt.

**Kleins Angriff** nutzt eine statistische Schlagseite in RC4: Pro Paket lässt sich
für jedes Schlüssel-Byte ein Tipp berechnen, der mit ~1,36/256 (statt 1/256) richtig
ist. Über zehntausende Pakete setzt sich der wahre Wert durch.

- Bei 64-bit-WEP (5 geheime Bytes) rekonstruiert Klein die **ersten 4 Bytes**.
- Das **5. Byte** wird per Brute-Force (256 Versuche) gegen den bekannten Klartext
  bestätigt — exakt das Standardverhalten von `aircrack-ng` (`-x1`, Default).

Das `.cap`-Parsing geschieht über einen **direkten pcap/802.11-Byte-Parser**
(kein `scapy` nötig), der radiotap/raw, QoS- und ToDS/FromDS-Frames abdeckt und
IVs dedupliziert.

---

## Voraussetzungen

- **Kali Linux** (oder vergleichbares Linux mit der aircrack-ng-Suite)
- **Root-Rechte** (`sudo`) für Monitor-Mode, Capture und Injection
- Ein **injection-fähiger WLAN-Adapter** mit Monitor-Mode
  (getestet mit ALFA **MT7921U**)
- Pakete:
  - `aircrack-ng`-Suite (`airodump-ng`, `aireplay-ng`, `airmon-ng`)
  - `python3` inkl. **Tkinter** (`sudo apt install python3-tk`)
- Ein eigener Test-AP, der auf **WEP** steht (z. B. NETGEAR WNR2200)

---

## Installation

```bash
git clone https://github.com/<dein-user>/<dein-repo>.git
cd <dein-repo>
sudo apt install aircrack-ng python3-tk
```

## Nutzung

**Live (am eigenen AP):**
```bash
sudo python3 wep_demo.py
```
1. „Scan" starten, Teil der eigenen SSID eintippen → wird grün hervorgehoben,
   „Dieses AP verwenden" klicken.
2. Capture läuft; mit **„Inject Traffic"** die ARP-Replay-Attacke starten,
   damit der IV-Zähler schnell hochläuft.
3. Bei genug IVs **„Crack zeigen"** → das Byte-Rennen läuft, am Ende steht der Schlüssel.

**Backup aus Datei:**
Im Tool „`.cap` laden" wählen und eine zuvor gesicherte Capture knacken.

---

## Konfiguration

Oben im Skript (Abschnitt `CONFIG`):

| Variable | Default | Bedeutung |
|---|---|---|
| `MODE` | `"live"` | `"live"` (echte Hardware) oder `"sim"` (Simulation) |
| `DEFAULT_IFACE` | `"wlan0"` | Managed-Interface, das in Monitor-Mode versetzt wird |
| `KEY_BITS` | `64` | Schlüssellänge (64-bit = 5 Byte, schnell für die Demo) |
| `ADAPTER_MODULE` | `"mt7921u"` | Kernel-Modul der Karte für den Reset |
| `RESET_ADAPTER` | `True` | Adapter bei jedem Scan-Start zurücksetzen |
| `CAPTURE_TARGET_IVS` | `50000` | empfohlene IV-Zahl bis zur Crack-Phase |
| `REPLAY_DURATION_SECS` | `35` | Gesamtdauer der Vote-Animation (größer = langsamer) |
| `CANDIDATES_SHOWN` | `10` | angezeigte Kandidaten pro Byte |

---

## Bekannte Einschränkungen

- Fest auf **64-bit-WEP** ausgelegt (für die Demo bewusst schnell). 128-bit wäre
  mit demselben Verfahren möglich, braucht nur mehr IVs.
- Injection-Verhalten hängt stark vom Adapter/Treiber ab (beim MT7921U half auf
  älteren Kerneln ein Firmware-Reinstall).
- Das Tool ist ein **Lehr-Werkzeug**, kein Ersatz für `aircrack-ng` im Produktiveinsatz.

---

## Hintergrund / Quellen

- Fluhrer, Mantin, Shamir — *Weaknesses in the Key Scheduling Algorithm of RC4* (2001)
- A. Klein — *Attacks on the RC4 stream cipher* (2005)
- Tews, Weinmann, Pyshkin — *Breaking 104-bit WEP in under a minute* (PTW, 2007)

