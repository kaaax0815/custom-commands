@echo off
if "%~1"=="" goto error
if "%~2"=="mp3" goto mp3
youtube-dl %1 --recode-video mp4 -f 22 --no-mtime
goto end

:mp3
youtube-dl %1 --extract-audio --audio-format mp3 --no-mtime

:error
echo No Url provided

:end