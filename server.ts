import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json({ limit: "2mb" }));

// Lazy initialize Gemini AI client
let aiClient: GoogleGenAI | null = null;
function getAIClient(): GoogleGenAI | null {
  if (!aiClient && process.env.GEMINI_API_KEY) {
    aiClient = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  }
  return aiClient;
}

// Health check endpoint
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// Live URL Security Header Auditor endpoint
app.get("/api/download-go", (_req, res) => {
  const filePath = path.join(process.cwd(), "main.go");
  res.download(filePath, "main.go");
});

app.get("/main.go", (_req, res) => {
  const filePath = path.join(process.cwd(), "main.go");
  res.sendFile(filePath);
});

app.post("/api/audit-url", async (req, res) => {
  try {
    const { url } = req.body || {};
    if (!url || typeof url !== "string") {
      return res.status(400).json({ success: false, error: "Debe ingresar una URL válida para analizar." });
    }

    let targetUrl = url.trim();
    if (!/^https?:\/\//i.test(targetUrl)) {
      targetUrl = "https://" + targetUrl;
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(targetUrl);
    } catch {
      return res.status(400).json({ success: false, error: `La URL '${targetUrl}' no tiene un formato válido.` });
    }

    const isHttps = parsedUrl.protocol === "https:";
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const startTime = Date.now();
    let response: Response;

    try {
      response = await fetch(targetUrl, {
        method: "GET",
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (KSec Web Security Auditor)",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
        },
        signal: controller.signal,
        redirect: "follow",
      });
    } catch (fetchErr: any) {
      clearTimeout(timeout);
      const isAbort = fetchErr.name === "AbortError" || controller.signal.aborted;
      const errMsg = isAbort
        ? "La solicitud excedió el tiempo límite de espera (10s). El servidor objetivo no respondió a tiempo."
        : fetchErr.cause?.message || fetchErr.message || "No se pudo conectar con el servidor web especificado.";

      return res.status(200).json({
        success: false,
        error: `Error de conexión con ${parsedUrl.hostname}: ${errMsg}`,
      });
    } finally {
      clearTimeout(timeout);
    }

    const latency = Date.now() - startTime;
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    return res.status(200).json({
      success: true,
      url: targetUrl,
      finalUrl: response.url || targetUrl,
      statusCode: response.status,
      statusText: response.statusText,
      isHttps,
      latency,
      headers,
    });
  } catch (err: any) {
    console.error("Audit URL unexpected error:", err);
    return res.status(200).json({
      success: false,
      error: err.message || "Ocurrió un error inesperado al procesar las cabeceras.",
    });
  }
});

// AI-powered MDN Security Audit & Advisor
app.post("/api/ai-audit", async (req, res) => {
  try {
    const { content, type, context } = req.body;
    if (!content || typeof content !== "string") {
      res.status(400).json({ error: "Se requiere contenido para la auditoría de IA" });
      return;
    }

    const ai = getAIClient();
    if (!ai) {
      res.status(503).json({
        error: "La clave de API de Gemini no está configurada. Por favor, configure GEMINI_API_KEY o utilice los analizadores basados en reglas.",
      });
      return;
    }

    const systemPrompt = `Eres un Arquitecto Principal de Seguridad Web y especialista en las especificaciones de seguridad web de MDN (Mozilla Developer Network).
Analiza la configuración de seguridad web provista, cabeceras, políticas o escenarios de amenazas según los estándares de Mozilla HTTP Observatory y las Guías Prácticas de Implementación de Seguridad de MDN.

Debes responder SIEMPRE EN ESPAÑOL con un informe Markdown exhaustivo, técnico, claro y estructurado.
Evalúa:
1. Puntos fuertes y cabeceras/directivas conformes a la normativa.
2. Vulnerabilidades, malas configuraciones y vectores de ataque (ej. XSS, Clickjacking, Confusión de tipos MIME, CSRF, Fuga de Tokens en Referer, ataques de canal lateral Spectre).
3. Fragmentos de remediación exacta y robusta listos para copiar (Express/Helmet, Nginx, Apache, Caddy, Cloudflare, Next.js).
4. Calificación de riesgo de la amenaza (Crítico, Alto, Medio, Bajo, Conforme) citando las guías de MDN correspondientes.`;

    const userPrompt = `Tipo de análisis: ${type || "general-security-audit"}
Contexto: ${context || "Revisión de seguridad para aplicación web"}
Contenido objetivo a analizar:
\`\`\`
${content}
\`\`\`

Genera un reporte completo en Markdown en español estructurado de la siguiente forma:
1. **Resumen Ejecutivo de Seguridad y Calificación MDN**
2. **Análisis Directo de Vulnerabilidades y Riesgos** (con escenarios de exploit prácticos)
3. **Auditoría Línea por Línea / Directiva por Directiva**
4. **Remediación Blindada para Producción** (fragmentos de código listos para Nginx, Express/Helmet y HTML)
5. **Referencias a las Guías Prácticas de MDN**`;

    const response = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: userPrompt,
      config: {
        systemInstruction: systemPrompt,
        temperature: 0.2,
      },
    });

    res.json({
      success: true,
      analysis: response.text || "No se pudo generar el análisis.",
    });
  } catch (err: any) {
    console.error("AI Audit error:", err);
    res.status(500).json({
      error: err.message || "Ocurrió un error durante el análisis de IA",
    });
  }
});

// Vite middleware for development vs static build in production
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Web Security Suite server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
