# 🚀 Detectar rama actual
$branch = git rev-parse --abbrev-ref HEAD
Write-Host "🔍 Estás en la rama: $branch"

# ⚠️ Verificar si hay archivos sin commit
$gitStatus = git status --porcelain

if ($gitStatus) {
    Write-Host "`n⚠️  Tienes archivos sin commit. Por favor guarda tus cambios antes de desplegar."
    Write-Host "`n🛠 Usa: git add . && git commit -m 'mensaje'`n"
    git status
    exit 1
}

# 📦 Definir nombre del servicio según la rama
switch ($branch) {
    "dev"  { $service = "mi-app-dev" }
    "main" { $service = "mi-app-prod" }
    default {
        Write-Host "❌ Rama no válida para despliegue automático. Solo se permite 'dev' o 'main'."
        exit 1
    }
}

# ☁️ Desplegar en Cloud Run
Write-Host "`n🚀 Desplegando '$service' desde la rama '$branch'..."
gcloud run deploy $service `
    --source . `
    --region us-central1 `
    --allow-unauthenticated

Write-Host "`n✅ Despliegue completado en Cloud Run: $service"
