# Path to your executable
$exePath = "C:\Users\patem\Documents\GitHub\AuthCoreVP\build\mingw_15-Release\client\client.exe"

# Target folder to copy DLLs
$targetDir = Split-Path $exePath

# Folder with Qt and MinGW DLLs
$mingwBin = "C:\msys64\mingw64\bin"

# Get the list of DLLs the exe depends on
$dlls = & "C:\msys64\mingw64\bin\objdump.exe" -p $exePath |
    Select-String "DLL Name:" |
    ForEach-Object { ($_ -split ":")[1].Trim() } |
    Sort-Object -Unique

Write-Host "Found $($dlls.Count) DLL dependencies:"
foreach ($dll in $dlls) {
    $src = Join-Path $mingwBin $dll
    if (Test-Path $src) {
        Copy-Item $src $targetDir -Force
        Write-Host "Copied: $dll"
    } else {
        Write-Host "Missing: $dll"
    }
}

Write-Host "Done! All found DLLs copied to $targetDir"
