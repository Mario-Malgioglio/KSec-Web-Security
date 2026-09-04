# 🦅 KSec - Auditor de Seguridad de Servidores Web

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Node Version](https://img.shields.io/badge/Node.js-18+-339933?style=flat&logo=nodedotjs)](https://nodejs.org)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react)](https://react.dev)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-v4-38B2AC?style=flat&logo=tailwind-css)](https://tailwindcss.com)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**KSec** es una herramienta de auditoría y diagnóstico de seguridad para servidores web y cabeceras HTTP, diseñada siguiendo las directrices de [Mozilla Observatory](https://observatory.mozilla.org/) y las [Guías Prácticas de Implementación de Seguridad Web de MDN](https://developer.mozilla.org/es/docs/Web/Security/Practical_implementation_guides).

Permite analizar cualquier sitio o servicio web en tiempo real, evaluar su postura de seguridad, obtener un puntaje global (0 a 100), generar reportes ejecutivos en PDF y obtener plantillas de configuración de remediación inmediata para servidores populares (**Nginx**, **Apache**, **Caddy**, **Cloudflare** y **Node.js/Express**).

---

## 📋 Tabla de Contenidos

- [Características Principales](#-características-principales)
- [Cabeceras y Vectores Auditados](#-cabeceras-y-vectores-auditados)
- [Arquitectura del Proyecto](#-arquitectura-del-proyecto)
- [Instalación y Uso](#-instalación-y-uso)
  - [Opción 1: Aplicación Go Standalone (Recomendada para escritorio)](#opción-1-aplicación-go-standalone)
  - [Opción 2: Entorno Web Full-Stack (React + Node.js)](#opción-2-entorno-web-full-stack)
- [Generación de Reportes PDF](#-generación-de-reportes-pdf)
- [Cierre y Liberación Automática de Memoria](#-cierre-y-liberación-automática-de-memoria)
- [Plantillas de Remediación](#-plantillas-de-remediación)
- [Contribuciones](#-contribuciones)
- [Licencia](#-licencia)

---

## 🚀 Características Principales

- **Auditoría HTTP Instantánea**: Inspección profunda de respuestas HTTP/HTTPS, códigos de estado, latencia de conexión y cadena de redirecciones.
- **Puntuación y Calificación (Scoring System)**: Algoritmo ponderado basado en severidad que clasifica la postura del servidor de `A+` a `F`.
- **Generación de Reportes en PDF**: Exporta un informe ejecutivo formal con diagnósticos técnicos, estado por cabecera y guía paso a paso de remediación.
- **Plantillas de Remediación Listas para Producción**: Fragmentos de configuración para Nginx, Apache, Caddy, Cloudflare y Express (Helmet).
- **Standalone sin Dependencias Externas (Go)**: Ejecutable único en Go con interfaz gráfica web integrada que se abre automáticamente en el navegador predeterminado.
- **Cierre Inteligente & Liberación de Memoria**: Cuando se cierra el navegador, el proceso en segundo plano se apaga automáticamente y devuelve la memoria física directamente al sistema operativo (`runtime.GC()` y `debug.FreeOSMemory()`).

---

## 🛡️ Cabeceras y Vectores Auditados

| Cabecera / Directiva | Propósito de Seguridad | Riesgo Mitigado |
| :--- | :--- | :--- |
| **Content-Security-Policy (CSP)** | Restringe orígenes de scripts, estilos, medios y objetos ejecutables | Cross-Site Scripting (XSS), Data Injection, Clickjacking |
| **Strict-Transport-Security (HSTS)** | Obliga al navegador a usar conexiones HTTPS cifradas (`includeSubDomains`, `preload`) | Man-in-the-Middle (MitM), SSL Strip, Downgrade Attacks |
| **X-Content-Type-Options** | Impide la interpretación errónea del tipo MIME (`nosniff`) | MIME Confusion Attacks, Drive-by Downloads |
| **X-Frame-Options / CSP frame-ancestors** | Controla si la página puede ser incrustada en `<frame>`, `<iframe>` u `<object>` | Clickjacking, UI Redressing |
| **Referrer-Policy** | Regula la cantidad de información enviada en el encabezado `Referer` | Fuga de tokens de sesión, URLs sensibles y privacidad |
| **Cross-Origin-Opener-Policy (COOP)** | Aísla el contexto de navegación en un grupo de contexto superior independiente | Cross-Origin Leaks, Spectre, XS-Leaks |
| **Cross-Origin-Embedder-Policy (COEP)** | Impide la carga de recursos de terceros sin autorización explícita | Ataques de canal lateral, Spectre, CORP bypass |
| **Permissions-Policy** | Deshabilita o restringe APIs del navegador (cámara, micrófono, geolocalización, etc.) | Abuso de permisos en iframes y accesos no autorizados |
| **Server / X-Powered-By** | Detecta exposición de versiones de software y servidores subyacentes | Reconocimiento y fingerprinting de vulnerabilidades conocidas |

---

## 🏗️ Arquitectura del Proyecto

El repositorio ofrece dos formas de ejecución según las necesidades del usuario:

```text
├── main.go               # Aplicación standalone en Go (servidor + UI embebida + PDF)
├── server.ts             # Servidor backend en Node.js/Express para proxy de auditoría
├── src/                  # Aplicación SPA React 19 + TypeScript
│   ├── components/       # Componentes de auditoría, navegación y modales de exportación
│   ├── data/             # Reglas, ponderaciones y estándares de Mozilla/MDN
│   ├── utils/            # Motor de generación de PDF y cálculos de seguridad
│   └── types/            # Tipos e interfaces TypeScript
├── index.html            # Entrypoint HTML de la aplicación web
├── package.json          # Dependencias y scripts de Node.js
└── vite.config.ts        # Configuración de compilación Vite + Tailwind CSS
```

---

## 💻 Instalación y Uso

### Opción 1: Aplicación Go Standalone

Ideal si deseas un único archivo ejecutable local sin necesidad de instalar Node.js ni paquetes `npm`.

#### Requisitos:
- [Go](https://go.dev/dl/) 1.21 o superior.

#### Ejecución directa:
```bash
go run main.go
```

#### Compilación de un binario distribuible:

**En Windows:**
```bash
go build -ldflags="-s -w" -o KSec.exe main.go
```

**En Linux / macOS:**
```bash
go build -ldflags="-s -w" -o ksec main.go
chmod +x ksec
./ksec
```

> **Nota**: Al iniciar, KSec abrirá automáticamente la interfaz en `http://localhost:8080`.

---

### Opción 2: Entorno Web Full-Stack

Ideal para desarrollo web, despliegues en servidores o personalización de la interfaz en React.

#### Requisitos:
- [Node.js](https://nodejs.org/) v18 o superior.
- Gestor de paquetes `npm` o `pnpm`.

#### Pasos:

1. **Instalar dependencias:**
   ```bash
   npm install
   ```

2. **Iniciar en modo desarrollo:**
   ```bash
   npm run dev
   ```
   El servidor estará disponible en `http://localhost:3000`.

3. **Compilar para producción:**
   ```bash
   npm run build
   npm start
   ```

---

## 📄 Generación de Reportes PDF

Tanto la versión en Go como la versión en React incluyen un motor integrado de generación de reportes vectoriales en PDF (usando `jsPDF` y `jspdf-autotable`):

- **Encabezado Institucional**: Identificación de auditoría bajo el estándar **KSec - Auditor de Servidores Web**.
- **Resumen Ejecutivo**: Fecha y hora de escaneo, tiempo de respuesta HTTP, código de estado y calificación global.
- **Tabla de Hallazgos**: Desglose de cada cabecera analizada con su valor detectado, estado (`Pasa`, `Advertencia`, `Falla`) y puntuación obtenida.
- **Plan de Acción y Remediación**: Recomendaciones técnicas precisas con fragmentos de configuración para subsanar cada falla detectada.

---

## ⚡ Cierre y Liberación Automática de Memoria

En la versión standalone (`main.go`):

1. **Monitoreo de Heartbeat**: La interfaz web envía pings periódicos al servidor en Go.
2. **Detección de Cierre**: Al cerrar la pestaña o la ventana del navegador (`beforeunload` / `pagehide`), se envía una señal mediante `navigator.sendBeacon`.
3. **Período de Gracia (1.5 segundos)**: Si el usuario presiona **F5 / Recargar**, el temporizador cancela el cierre, evitando interrupciones accidentales.
4. **Liberación de Memoria al SO**:
   - Ejecuta `runtime.GC()` para limpiar el heap de Go.
   - Ejecuta `debug.FreeOSMemory()` para devolver de inmediato la memoria física no utilizada al sistema operativo.
   - Finaliza el proceso limpiamente (`os.Exit(0)`).
5. **Botón Manual**: También incluye un botón **"Cerrar Aplicativo"** en la barra de navegación para un apagado inmediato.

---

## 🧩 Plantillas de Remediación

KSec provee fragmentos de configuración listos para producción para añadir las cabeceras recomendadas:

### Nginx (`nginx.conf` o bloque `server`)
```nginx
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
```

### Apache (`.htaccess` o `httpd.conf`)
```apache
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
</IfModule>
```

---

## 🤝 Contribuciones

Las contribuciones, reportes de errores y sugerencias son bienvenidos:

1. Haz un Fork del proyecto.
2. Crea una rama para tu función (`git checkout -b feature/nueva-cabecera`).
3. Confirma tus cambios (`git commit -m 'feat: soporte para nueva cabecera'`).
4. Haz push a la rama (`git push origin feature/nueva-cabecera`).
5. Abre un **Pull Request**.

---

## 📜 Licencia

Este proyecto se distribuye bajo la licencia **MIT**. Consulta el archivo `LICENSE` para más detalles.
