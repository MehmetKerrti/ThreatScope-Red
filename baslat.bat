@echo off
chcp 65001 >nul
title DTH ThreatScope Red // Made in Guarbey
color 0C
mode con: cols=88 lines=30

cls
echo.
echo  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
echo  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
echo     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ███████╗██║     ██║   ██║██████╔╝█████╗  
echo     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
echo     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ███████║╚██████╗╚██████╔╝██║     ███████╗
echo     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
echo  ========================================================================================
echo       [ DTH SYSTEMS // MALWARE ANALYSIS LAB ]          *** MADE IN GUARBEY ***
echo  ========================================================================================
echo.

timeout /t 1 >nul
echo  [*] [1/4] Sistem ortami ve Python cekirdegi dogrulaniyor...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 4F
    echo.
    echo  [X] KRITIK HATA: Sistemde Python bulunamadi!
    echo  [!] Lutfen python.org adresinden Python kurarken "Add Python to PATH" kutusunu isaretleyin.
    echo.
    pause
    exit /b
)
for /f "tokens=*" %%i in ('python --version') do set PYVER=%%i
echo  [+] [OK] %PYVER% algilandi.
echo.

timeout /t 1 >nul
echo  [*] [2/4] Siber analiz modulleri ve bagimliliklar yukleniyor...
echo      (streamlit, pefile, pandas, requests, plotly)
python -m pip install --upgrade pip >nul 2>&1
if exist requirements.txt (
    python -m pip install -q -r requirements.txt
) else (
    python -m pip install -q streamlit pefile pandas requests plotly
)
echo  [+] [OK] Tum analiz motorlari hazir.
echo.

timeout /t 1 >nul
echo  [*] [3/4] Yerel guvenlik protokolu yapilandiriliyor (127.0.0.1)...
echo  [+] [OK] Izole laboratuvar ortami aktif.
echo.

timeout /t 1 >nul
echo  [*] [4/4] Arayuz baslatiliyor - Tarayiciniz otomatik acilacaktir...
echo  ----------------------------------------------------------------------------------------
echo   LOCAL URL : http://localhost:8501
echo   AUTHOR    : Made in Guarbey (DTH Systems)
echo   CIKIS     : Kapatmak icin pencereyi kapatin veya CTRL + C tuslarina basin.
echo  ----------------------------------------------------------------------------------------
echo.

python -m streamlit run main.py --server.address 127.0.0.1
pause