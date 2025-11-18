# Instrucciones de Usuario - Importación desde Google Drive

Este documento proporciona instrucciones paso a paso para configurar la importación automática de archivos desde Google Drive a este repositorio de GitHub.

## Resumen del Problema Resuelto

**Error original:** "Neither input download-from nor upload-to has been specified"

**Causa:** El workflow de GitHub Actions no tenía configurados los parámetros requeridos para el action de Google Drive.

**Solución:** Se actualizó el workflow para incluir los parámetros `download-from` y `download-to`, y se simplificó eliminando pasos redundantes.

---

## Configuración Inicial (Se hace una sola vez)

### Paso 1: Crear Proyecto en Google Cloud

1. Ir a [Google Cloud Console](https://console.cloud.google.com/)
2. Iniciar sesión con tu cuenta de Google
3. Crear nuevo proyecto:
   - Clic en el selector de proyectos (parte superior)
   - Clic en **"Nuevo Proyecto"**
   - Nombre: "GitHub-GDrive-RM330" (o el que prefieras)
   - Clic en **"Crear"**
4. Seleccionar el proyecto recién creado
5. Habilitar Google Drive API:
   - Ir a **"APIs y servicios"** → **"Biblioteca"**
   - Buscar "Google Drive API"
   - Clic en **"Habilitar"**

### Paso 2: Crear Credenciales OAuth 2.0

1. Ir a **"APIs y servicios"** → **"Credenciales"**
2. Clic en **"Crear credenciales"** → **"ID de cliente de OAuth"**
3. Si se solicita, configurar pantalla de consentimiento:
   - Clic en **"Configurar pantalla de consentimiento"**
   - Seleccionar **"Externo"** → **"Crear"**
   - Completar campos requeridos:
     - Nombre de aplicación: "GitHub GDrive Import"
     - Correo de soporte: tu email
     - Información de contacto: tu email
   - Clic en **"Guardar y Continuar"** en todos los pasos
   - Volver a **"Credenciales"**
4. Crear credenciales nuevamente:
   - Clic en **"Crear credenciales"** → **"ID de cliente de OAuth"**
   - Tipo de aplicación: **"Aplicación de escritorio"**
   - Nombre: "Skicka Client"
   - Clic en **"Crear"**
5. **IMPORTANTE:** Copiar y guardar:
   - **ID de cliente** (formato: `xxxxx.apps.googleusercontent.com`)
   - **Secreto de cliente** (cadena aleatoria)

### Paso 3: Instalar y Configurar Skicka en tu Computadora

Skicka es la herramienta que permite la autenticación con Google Drive.

#### Instalación según tu sistema operativo:

**macOS (con Homebrew):**
```bash
brew install skicka
```

**Linux:**
```bash
wget https://github.com/google/skicka/releases/download/v0.8.0/skicka-v0.8.0-linux-amd64
chmod +x skicka-v0.8.0-linux-amd64
sudo mv skicka-v0.8.0-linux-amd64 /usr/local/bin/skicka
```

**Windows:**
Descargar desde [Skicka Releases](https://github.com/google/skicka/releases) y agregar al PATH.

#### Configuración:

1. Inicializar skicka:
```bash
skicka init
```

2. Editar el archivo de configuración (`~/.skicka.config` en macOS/Linux, `%USERPROFILE%\.skicka.config` en Windows):
```json
{
  "clientid": "TU_CLIENT_ID_DEL_PASO_2",
  "clientsecret": "TU_CLIENT_SECRET_DEL_PASO_2"
}
```

3. Autenticar (se abrirá el navegador):
```bash
skicka ls /
```

4. Iniciar sesión, otorgar permisos y volver a la terminal

5. Copiar el contenido del token:

**macOS/Linux:**
```bash
cat ~/.skicka.tokencache.json
```

**Windows:**
```cmd
type %USERPROFILE%\.skicka.tokencache.json
```

Copiar TODO el contenido JSON (empieza con `{"access_token":...`)

### Paso 4: Configurar Secrets en GitHub

1. Ir al repositorio en GitHub → **"Settings"** → **"Secrets and variables"** → **"Actions"**
2. Agregar tres secrets (clic en **"New repository secret"** para cada uno):

| Nombre del Secret | Valor |
|------------------|-------|
| `GOOGLE_CLIENT_ID` | Tu Client ID del Paso 2 |
| `GOOGLE_CLIENT_SECRET` | Tu Client Secret del Paso 2 |
| `GOOGLE_DRIVE_TOKEN` | El JSON completo del Paso 3 |

---

## Cómo Usar el Workflow

### Ejecutar Importación Manual

1. Ir a la pestaña **Actions** en GitHub
2. Seleccionar **"Import Files from Google Drive"**
3. Clic en **"Run workflow"**
4. Completar los campos:
   - **Folder path**: Ruta de la carpeta en Google Drive (ver abajo)
   - **Target path**: Dónde guardar en el repositorio (default: `./`)
5. Clic en **"Run workflow"**

### Entender las Rutas de Carpetas

El workflow usa **rutas de carpetas**, NO URLs ni IDs de carpetas.

**Ejemplos:**
- Carpeta en la raíz llamada "Datos": `/Datos`
- Carpeta anidada: `/Trabajo/Proyectos/RM330`
- Subcarpeta: `/MisDocs/Reportes/2024`

**Importante:**
- Las rutas deben empezar con `/`
- Usar la estructura tal como aparece en "Mi unidad"
- Las rutas distinguen mayúsculas/minúsculas

**Verificar la ruta localmente:**
```bash
skicka ls /                    # Listar carpetas raíz
skicka ls /MiCarpeta          # Listar contenido de una carpeta
skicka ls /MiCarpeta/Subcarpeta  # Navegar más profundo
```

### Qué Hace el Workflow

1. ✓ Descarga el repositorio
2. ✓ Se conecta a Google Drive con tus credenciales
3. ✓ Descarga todos los archivos de la carpeta especificada
4. ✓ Los guarda en la ruta destino del repositorio
5. ✓ Automáticamente hace commit y push de los cambios

El parámetro `remove-outdated: true` asegura que si borras archivos en Google Drive, también se borrarán del repositorio en la próxima sincronización.

---

## Solución de Problemas

### "Neither input download-from nor upload-to has been specified"

**Causa:** Workflow desactualizado.

**Solución:** Asegurarse de tener la versión actualizada del workflow de este repositorio.

### "Permission denied" o "Authentication failed"

**Causa:** Credenciales inválidas o expiradas.

**Solución:**
1. Verificar que los tres secrets estén configurados correctamente
2. Regenerar token:
   ```bash
   skicka ls /
   ```
3. Actualizar el secret `GOOGLE_DRIVE_TOKEN` con el nuevo token

### "Folder not found"

**Causa:** Ruta incorrecta.

**Solución:**
1. Verificar la ruta localmente:
   ```bash
   skicka ls /
   skicka ls /TuCarpeta
   ```
2. Usar la ruta exacta (sensible a mayúsculas/minúsculas)
3. Asegurar que la ruta empiece con `/`
4. Verificar tener acceso a la carpeta en Google Drive

### "No changes to commit"

**Causa:** La carpeta existe pero no se descargaron archivos.

**Posibles razones:**
- Carpeta vacía en Google Drive
- Ruta incorrecta
- Sin acceso a la carpeta
- Archivos ya existen y no han cambiado

**Solución:**
- Revisar los logs del workflow en Actions
- Verificar que la carpeta contenga archivos en Google Drive
- Confirmar que tu cuenta tiene acceso

### Token Expirado

Los tokens OAuth de Google pueden expirar.

**Síntomas:** El workflow funcionaba antes pero ahora falla con errores de autenticación.

**Solución:** Regenerar el token (Paso 3) y actualizar el secret `GOOGLE_DRIVE_TOKEN`.

---

## Mejores Prácticas

### 1. Probar con Carpetas Pequeñas Primero
Antes de importar grandes cantidades de datos, probar con una carpeta pequeña.

### 2. Organizar Google Drive
Mantener archivos en carpetas con nombres claros y rutas predecibles:
- ✓ Bueno: `/Importaciones-GitHub/RM330-Datos`
- ✗ Evitar: `/Mis Documentos/Varios/Cosas/Aleatorio/Datos`

### 3. Considerar Límites de Tamaño
- GitHub tiene límites de tamaño de archivo (100 MB recomendado máximo)
- Archivos grandes pueden fallar al hacer commit
- Límite de tamaño de repositorio típicamente 1-5 GB

### 4. Usar Rutas Específicas
Importar carpetas específicas en lugar de todo Drive:
- ✓ Bueno: `/Proyectos/RM330/Archivos`
- ✗ Evitar: `/` (todo Drive)

### 5. Monitorear Ejecuciones
Revisar la pestaña Actions después de cada ejecución para verificar éxito.

---

## Notas de Seguridad

⚠️ **IMPORTANTE:**
- Nunca hacer commit del archivo de token o credenciales al repositorio
- Siempre almacenar credenciales en GitHub Secrets
- Tratar el token como una contraseña - otorga acceso a tu Google Drive
- Considerar crear una cuenta de Google dedicada para automatización
- Revisar y rotar credenciales regularmente

---

## Lista de Verificación de Configuración

- [ ] Proyecto de Google Cloud creado
- [ ] Google Drive API habilitada
- [ ] Credenciales OAuth 2.0 creadas
- [ ] Skicka instalado en máquina local
- [ ] Skicka configurado con credenciales
- [ ] Autenticado con Google y token generado
- [ ] Secret `GOOGLE_CLIENT_ID` agregado en GitHub
- [ ] Secret `GOOGLE_CLIENT_SECRET` agregado en GitHub
- [ ] Secret `GOOGLE_DRIVE_TOKEN` agregado en GitHub
- [ ] Ruta de carpeta verificada con `skicka ls`
- [ ] Workflow probado con carpeta pequeña

---

## Resumen de la Corrección

### Cambios Realizados en el Workflow:

1. **Agregado parámetro `download-from`**: Especifica la carpeta de Google Drive desde donde descargar
2. **Agregado parámetro `download-to`**: Especifica dónde guardar los archivos en el repositorio
3. **Agregado parámetro `remove-outdated: true`**: Sincroniza eliminaciones
4. **Eliminado paso manual redundante**: El action ahora maneja todo el proceso de descarga

### Configuración Actualizada:

```yaml
- name: Download files from Google Drive
  uses: satackey/action-google-drive@v1.2.1
  with:
    skicka-tokencache-json: ${{ secrets.GOOGLE_DRIVE_TOKEN }}
    google-client-id: ${{ secrets.GOOGLE_CLIENT_ID }}
    google-client-secret: ${{ secrets.GOOGLE_CLIENT_SECRET }}
    download-from: ${{ inputs.folder_path }}
    download-to: ${{ inputs.target_path }}
    remove-outdated: true
```

El workflow ahora funciona correctamente y está listo para usar una vez completada la configuración de secrets.

---

## Soporte

Para más información, consultar:
- [README.md](./Readme.md) - Documentación completa en inglés
- [Documentación de Skicka](https://github.com/google/skicka)
- [action-google-drive](https://github.com/satackey/action-google-drive)
