Write-Host "🧼 Cleaning up old build files..."
Remove-Item -Recurse -Force build, dist, StegoPix.spec -ErrorAction SilentlyContinue

Write-Host "🛠 Building new StegoPix.exe..."
pyinstaller --onefile --windowed --name="StegoPix" stegopix.py

if (Test-Path ".\dist\StegoPix.exe") {
    Write-Host "✅ Build complete!"
    explorer.exe .\dist\
} else {
    Write-Host "❌ Build failed! Check the PyInstaller output for errors."
}

#to automatically make another build for windows. 