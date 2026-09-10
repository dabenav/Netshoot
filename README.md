# Netshoot

Scripts de diagnóstico de red para **Windows** (`ts.ps1`) y **macOS** (`ts.sh`). Recopilan información del equipo y de la conexión, ejecutan pruebas de conectividad y velocidad, y envían un reporte de texto al servidor de soporte.

## Windows

Abre **Símbolo del sistema (CMD)** y ejecuta:

```bat
powershell "iwr https://bit.ly/3rvXpP6 -O ts.ps1 -ea Stop" && powershell -ex bypass -f ts.ps1
```

El comando descarga `ts.ps1` en la carpeta actual y lo ejecuta si la descarga finaliza correctamente. Utiliza una carpeta donde tengas permisos de escritura.

Requisitos:

- Windows con Windows PowerShell 5.1.
- Windows de 64 bits compatible con el ejecutable x64 de Speedtest incluido en el repositorio.
- Conexión a Internet para descargar los archivos y enviar el reporte.

## macOS

Abre **Terminal** y ejecuta:

```bash
curl -fL 'https://bit.ly/NetTsMac' -o ts.sh && /bin/bash ts.sh
```

El comando descarga `ts.sh` en la carpeta actual y lo ejecuta si la descarga finaliza correctamente. Utiliza una carpeta donde tengas permisos de escritura. No requiere instalar PowerShell ni Homebrew; ejecútalo inicialmente sin `sudo`.

El script descarga el ejecutable de Speedtest para macOS desde este repositorio y le asigna permisos de ejecución automáticamente.

## Qué hace el diagnóstico

- Recopila información del equipo y de la interfaz de red activa.
- Consulta información de WiFi o Ethernet disponible en el sistema.
- Ejecuta pruebas de ping, ruta, resolución DNS y conectividad a puertos 80 y 443.
- Ejecuta **dos pruebas de Speedtest**, con una pausa de **3 segundos**, y muestra los resultados en el formato nativo de Ookla.
- Consulta los registros de red de las últimas 24 horas accesibles al usuario.
- Captura la salida en un reporte de texto y lo envía al servidor de soporte configurado.

Las consultas de WiFi y registros dependen de los permisos del sistema. La salida de Windows y macOS no es idéntica: utilizan herramientas y registros diferentes. En macOS, algunos datos como SSID y BSSID pueden estar ocultos.

## Reporte y código de soporte

El nombre del reporte tiene este formato:

```text
HOSTNAME_yyyy-MM-dd_HH-mm-ss-fff.txt
```

Cuando el servidor confirma el envío, se muestra un mensaje como este:

```text
El reporte de texto fue enviado correctamente.

Por favor, envie este codigo al Departamento de Soporte: DANIDEA_2026-09-10_11-35-33-482.txt
```

Comparte el código mostrado con el Departamento de Soporte. Un envío correcto confirma la recepción del reporte; no significa que todas las pruebas de red hayan sido satisfactorias.

El reporte puede contener información del equipo, direcciones IP y MAC, detalles de la conexión y registros de red.

## Limpieza de archivos

Los scripts están diseñados para eliminar el ejecutable descargado, el reporte temporal y el propio script. No se conserva una copia local del reporte para reintentar el envío.

Si ocurre un cierre forzado del proceso o un apagado, la limpieza puede quedar incompleta. En Windows, utiliza una carpeta sin archivos propios llamados `ts.ps1` o `speedtest.exe`; la ejecución descarga y elimina archivos con esos nombres. En macOS, la descarga inicial reemplaza un archivo existente llamado `ts.sh` en la carpeta actual.

## Archivos del repositorio

| Archivo | Uso |
| --- | --- |
| `ts.ps1` | Diagnóstico para Windows. |
| `ts.sh` | Diagnóstico para macOS. |
| `speedtest.exe` | Ejecutable de Ookla para Windows. |
| `speedtest` | Ejecutable de Ookla para macOS. |

Los enlaces cortos deben apuntar a la descarga **Raw** de los scripts correspondientes, no a la página de visualización de GitHub.

## Estado de validación

Speedtest se probó en Windows PowerShell ISE 5.1 con `--accept-license --accept-gdpr`, completando las dos pruebas sin los mensajes de error observados anteriormente.

La versión de macOS tiene validación de sintaxis, pero aún requiere una prueba completa en un Mac real para confirmar las consultas de red, los registros y el envío del reporte.
