# 📶 Hiraya Wifi Hotspot

A simple Windows desktop app that turns your extra Wi-Fi receiver (USB / PCIe Wi-Fi adapter) into a hotspot and shares your internet connection (e.g. Ethernet) with phones, tablets, and other devices.

## Features

- **One-click hotspot** – set a network name and password, then press **Start Hotspot**
- **Internet sharing** – shares any adapter (Ethernet, another Wi-Fi, etc.) through Windows Internet Connection Sharing (ICS)
- **Scan-to-connect QR code** – phones can join instantly by pointing the camera at the code (with an enlarged view for guests)
- **Connected devices list** – shows MAC and IP addresses of connected clients, refreshed live
- **Self-healing ICS** – automatically clears stale sharing entries left by removed adapters / uninstalled hotspot apps (fixes `0x80040201`)
- **Remembers settings** – saved to `%APPDATA%\HirayaWifiHotspot\config.json`
- Dark, modern UI, no console window

## Requirements

- Windows 10 / 11
- A Wi-Fi adapter whose driver supports **Hosted Network**
  Check with: `netsh wlan show drivers` → `Hosted network supported : Yes`
- Administrator rights (the app requests elevation automatically)
- Python 3.10+ (only if running from source)

## Run from source

```powershell
pip install -r requirements.txt
python hiraya_wifi_hotspot.py
```

Or double-click **`Hiraya Wifi Hotspot.bat`**.

## Build a standalone .exe

Double-click **`build_exe.bat`**, or run:

```powershell
pip install pyinstaller qrcode
python -m PyInstaller --noconfirm --onefile --windowed --uac-admin --hidden-import qrcode --name "Hiraya Wifi Hotspot" hiraya_wifi_hotspot.py
```

The app will be at `dist\Hiraya Wifi Hotspot.exe`.

## How it works

1. `netsh wlan set hostednetwork` / `start hostednetwork` creates the hotspot on the Wi-Fi adapter.
2. The `HNetCfg.HNetShare` COM API enables ICS from the selected source adapter to the hosted network adapter (clients get `192.168.137.x` addresses).
3. Stopping the hotspot turns off the hosted network and disables sharing.

## Troubleshooting

| Problem | Fix |
|---|---|
| `Hosted network supported : No` | Update the Wi-Fi adapter driver, or use an adapter that supports it |
| `The hosted network couldn't be started` | Make sure Wi-Fi is on and Airplane mode is off |
| Internet sharing fails (`0x80040201`) | Quit other hotspot tools (Connectify, mHotspot, etc.). The app auto-clears stale ICS entries on each start |
| Devices connect but have no internet | Ensure the correct source adapter is selected under **Share internet from** |
