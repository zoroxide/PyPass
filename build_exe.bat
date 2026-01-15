@echo off
echo Building PyPass executable...
echo.

REM Clean previous builds
if exist "dist" rmdir /s /q dist
if exist "build" rmdir /s /q build
if exist "PyPass.spec" del PyPass.spec

REM Build executable
.venv\Scripts\pyinstaller.exe --onefile ^
    --windowed ^
    --name PyPass ^
    --icon assets\icon.ico ^
    --add-data "assets;assets" ^
    --exclude-module tests ^
    --exclude-module pytest ^
    main.py

REM Note: Database files (*.db) are automatically excluded and created per-user on first run

echo.
echo Build complete! Executable is in the 'dist' folder.
pause
