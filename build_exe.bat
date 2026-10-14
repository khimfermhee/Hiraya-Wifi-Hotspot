@echo off
cd /d "%~dp0"
python -m pip install --upgrade pyinstaller qrcode
python -m PyInstaller --noconfirm --onefile --windowed --uac-admin --hidden-import qrcode --name "Hiraya Wifi Hotspot" hiraya_wifi_hotspot.py
echo.
echo Done. Your app is at: %~dp0dist\Hiraya Wifi Hotspot.exe
pause
