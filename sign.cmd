@echo off
if "%~1"=="" goto error
gpg --output %1.sig --detach-sig %1
goto end

:error
echo Sytax: sign <input>

:end