@echo off
if "%~1"=="" goto error
echo Pulling changes
git pull origin %1
echo Pushing changes
git push origin %1
goto end

:error
echo No Branch selected

:end