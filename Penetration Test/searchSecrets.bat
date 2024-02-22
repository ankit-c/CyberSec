@echo off

rem Specify the file containing keywords
set "KEYWORDS_FILE=C:\path\to\keywords.txt"

rem Specify the directory to search
set "SEARCH_DIR=C:\"

rem Specify the output file
set "OUTPUT_FILE=C:\path\to\out.txt"

rem Loop through each keyword in the file and perform the search
(for /f "tokens=*" %%K in (%KEYWORDS_FILE%) do (
    echo Searching for "%%K"...
    findstr /si /m /c:"%%K" "%SEARCH_DIR%\*.ini"
)) > "%OUTPUT_FILE%"

echo Search completed. Results saved to "%OUTPUT_FILE%"
