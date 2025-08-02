# ERP Mi Mentor de Inversión

Este repositorio contiene el código fuente del sistema ERP de la empresa **Mi Mentor de Inversión**, incluyendo el panel de alumnos, backend en Flask, y despliegue automatizado en Google Cloud Run.

---

## 🚀 Flujo de trabajo y despliegue

Trabajamos con un enfoque de **ambientes separados** para desarrollo y producción:

| Entorno      | Rama Git | Servicio Cloud Run | Trigger CI/CD |
|--------------|----------|--------------------|----------------|
| Desarrollo   | `dev`    | `mi-app-dev`       | `deploy-dev`   |
| Producción   | `main`   | `mi-app-prod`      | `deploy-prod`  |

---

## 🛠 Despliegue manual

Puedes desplegar manualmente desde PowerShell usando:

```powershell
.\deploy.ps1
