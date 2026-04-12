# Script de reparation de l'environnement virtuel pour le notebook WAF
# Executez ce script APRES avoir ferme VS Code completement

Set-Location $PSScriptRoot

Write-Host "=== Suppression de l'ancien venv ===" -ForegroundColor Cyan
Remove-Item -Recurse -Force .venv -ErrorAction SilentlyContinue
Write-Host "Ancien venv supprime." -ForegroundColor Green

Write-Host "=== Creation du venv avec Python 3.12 ===" -ForegroundColor Cyan
C:\Users\wizab\AppData\Local\Programs\Python\Python312\python.exe -m venv .venv
Write-Host "Venv cree." -ForegroundColor Green

Write-Host "=== Installation des dependances ===" -ForegroundColor Cyan
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install numpy pandas matplotlib seaborn scikit-learn joblib scipy ipykernel

Write-Host "=== Verification des imports ===" -ForegroundColor Cyan
.venv\Scripts\python.exe -c "
import numpy as np
import pandas as pd
import matplotlib
import seaborn as sns
import sklearn
import joblib
import sys
print('Python', sys.version[:6])
print('numpy', np.__version__)
print('pandas', pd.__version__)
print('sklearn', sklearn.__version__)
print('ENVIRONNEMENT OK - Rouvrez VS Code et relancez le notebook.')
"
