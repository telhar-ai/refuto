@echo off
REM Lanzador del CLI de refuto para cmd.exe y PowerShell. Existe para que `refuto verify`
REM (que es como lo escribe toda la documentacion) sea un comando de verdad y no una
REM abreviatura que el lector traduce a mano. Sin el, la primera orden del manual responde
REM "The term 'refuto' is not recognized", que es un mal primer minuto.
REM
REM Se resuelve solo: refuto es el directorio de arriba, no el directorio actual. Eso
REM importa porque este comando se invoca DESDE el espacio gobernado, que esta en otro sitio.
setlocal

set "REFUTO_PY=%~dp0..\refuto.py"
if not exist "%REFUTO_PY%" (
  echo refuto: no encuentro refuto.py junto a este lanzador. 1>&2
  exit /b 2
)

set "PY="
for %%C in (python3.exe python.exe py.exe) do (
  if not defined PY for %%F in ("%%~$PATH:C") do if not "%%~F"=="" set "PY=%%~F"
)
if not defined PY (
  echo refuto: no hay interprete de Python. Se necesita 3.10 o superior. 1>&2
  exit /b 2
)

"%PY%" "%REFUTO_PY%" %*
exit /b %ERRORLEVEL%
