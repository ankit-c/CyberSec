@echo off

rem Specify the file containing keywords
set "KEYWORDS_FILE=keywords.txt"

rem Specify the directory to search
set "SEARCH_DIR=C:\"

rem Specify the output file
set "OUTPUT_FILE=out.txt"

rem Specify the file types to search
set "FILE_TYPES=*.ini *.config *.txt *.env *.properties *.xml *.json"

rem Clear the output file before appending new results
echo. > "%OUTPUT_FILE%"

rem Loop through each keyword in the file and perform the search across multiple file types
(for /f "tokens=*" %%K in (%KEYWORDS_FILE%) do (
    echo Searching for "%%K"...
    for %%F in (%FILE_TYPES%) do (
        findstr /si /m /c:"%%K" "%SEARCH_DIR%\%%F"
    )
)) >> "%OUTPUT_FILE%"

echo Search completed. Results saved to "%OUTPUT_FILE%"
