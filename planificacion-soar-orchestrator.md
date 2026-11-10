# Planificación — Proyecto 3: Orquestador de Respuesta a Incidentes (SOAR Simplificado)

**Nombre tentativo del repo:** `ai-incident-response-orchestrator`
**Autor:** Nachitzu
**Estado:** Planificación
**Última actualización:** Julio 2026

---

## 1. Objetivo

Construir un sistema multi-agente que simule el flujo completo de respuesta a incidentes de un SOC: **detección → investigación → respuesta**. El objetivo no es un SOAR de producción, sino demostrar comprensión end-to-end del ciclo de vida de un incidente y capacidad de diseñar arquitecturas multi-agente con responsabilidades separadas.

Este proyecto es la evolución natural del SOC Triage Agent: aquel resolvía triage de Tier 1 con un solo agente; este demuestra orquestación y colaboración entre agentes especializados, que es el patrón que las empresas están adoptando en seguridad.

### Objetivos secundarios

- Pieza central del portafolio para postulaciones remotas (EU/US).
- Material para 2-3 posts de LinkedIn (español e inglés) durante el desarrollo, no solo al final.
- Reutilizar y consolidar componentes del SOC Triage Agent (parsing de alertas, mapeo MITRE ATT&CK, modelos Pydantic).

---

## 2. Alcance

### Dentro del alcance (v1)

- **Agente Detector:** recibe eventos/alertas crudas (JSON simulado o dataset), filtra ruido, decide si algo amerita escalar a investigación. Produce un `Incident` estructurado.
- **Agente Investigador:** enriquece el incidente. Correlaciona IOCs contra threat intel (feeds gratuitos u offline), mapea a técnicas MITRE ATT&CK, arma una hipótesis del ataque y un nivel de confianza.
- **Agente de Respuesta:** a partir de la investigación, sugiere un playbook: pasos de contención, erradicación y recuperación priorizados. Marca cuáles pasos requieren aprobación humana (human-in-the-loop).
- **Orquestador:** coordina el flujo entre agentes, mantiene el estado del incidente, y produce un reporte final del caso.
- **Salida:** reporte de incidente en Markdown/JSON con toda la cadena de razonamiento auditable.
- **CLI** como interfaz (igual que el triage agent, mantiene consistencia del portafolio).

### Fuera del alcance (v1)

- Ejecución real de acciones de respuesta (aislar hosts, bloquear IPs). Solo *sugerencia* de playbook.
- Integración con SIEM/EDR reales (Splunk, Sentinel, etc.). Se puede dejar como interfaz abstracta para v2.
- UI web (posible v2 con dashboard simple).
- Entrenamiento de modelos propios.

---

## 3. Arquitectura

```
Eventos/Alertas (dataset o simulados)
        │
        ▼
┌─────────────────┐
│ Agente Detector  │──► descarta falsos positivos obvios
└────────┬────────┘
         │ Incident (Pydantic)
         ▼
┌─────────────────────┐     ┌──────────────────────┐
│ Agente Investigador  │◄───►│ Threat Intel (tools)  │
│ - correlación IOCs   │     │ - feeds locales/API   │
│ - mapeo ATT&CK       │     │ - reputación IP/hash  │
└────────┬────────────┘     └──────────────────────┘
         │ Investigation (Pydantic)
         ▼
┌─────────────────────┐
│ Agente de Respuesta  │──► Playbook sugerido + flags HITL
└────────┬────────────┘
         │
         ▼
   Reporte final (MD/JSON) + log auditable
```

### Decisiones de diseño clave

1. **Contratos estrictos entre agentes:** cada agente recibe y devuelve modelos Pydantic v2 (`RawEvent`, `Incident`, `Investigation`, `ResponsePlan`). Esto es lo que diferencia un sistema serio de un demo: los agentes no se pasan texto libre.
2. **Threat intel como *tools*, no como prompt:** el investigador usa tool calling para consultar reputación de IPs/hashes/dominios. Fuentes candidatas: AbuseIPDB (free tier), listas locales de MITRE ATT&CK, feeds OTX de AlienVault, o un dataset offline para que el demo funcione sin API keys.
3. **Human-in-the-loop explícito:** el playbook distingue acciones automáticas seguras (ej. "abrir ticket") de acciones destructivas que requieren aprobación (ej. "aislar host"). Esto demuestra madurez de blue team.
4. **Trazabilidad:** cada decisión de cada agente queda en un log estructurado. Un analista debe poder auditar por qué el sistema llegó a cada conclusión — misma filosofía de interpretabilidad de la tesis.

### Stack

| Componente | Elección | Nota |
|---|---|---|
| Lenguaje | Python 3.11+ | consistente con triage agent |
| LLM | Anthropic SDK (`anthropic`) | tool use para threat intel; verificar modelo vigente en docs.claude.com antes de fijarlo |
| Validación | Pydantic v2 | contratos entre agentes |
| Framework de ATT&CK | `mitreattack-python` o JSON de STIX local | reutilizar del proyecto anterior |
| CLI | Typer o argparse | Typer da mejor DX |
| Datos de prueba | Microsoft GUIDE (subset) + alertas sintéticas | ya investigaste GUIDE, se reutiliza |
| Tests | pytest | mínimo: contratos Pydantic + flujo e2e con mocks |

---

## 4. Fases y cronograma

Estimación pensada para compatibilizar con la preparación del Security+ (agosto–septiembre). Ritmo asumido: 8–10 h/semana.

### Fase 0 — Diseño y esqueleto (Semana 1)
- [ ] Definir los 4 modelos Pydantic centrales (`RawEvent`, `Incident`, `Investigation`, `ResponsePlan`).
- [ ] Estructura del repo, README inicial con diagrama de arquitectura, licencia.
- [ ] Preparar 10–15 escenarios de prueba (mezcla: phishing, brute force, malware beaconing, exfiltración, falsos positivos).
- **Entregable:** repo público con diseño documentado. *Post LinkedIn #1: anuncio del proyecto y arquitectura.*

### Fase 1 — Agente Detector (Semanas 2–3)
- [ ] Ingesta de eventos desde JSON/dataset.
- [ ] Lógica de detección: prompt + criterios de escalamiento con salida estructurada.
- [ ] Manejo de falsos positivos obvios (debe descartar, no escalar todo).
- [ ] Tests con los escenarios de la Fase 0.
- **Criterio de salida:** dado un lote mixto de eventos, escala los correctos y descarta ruido con justificación.

### Fase 2 — Agente Investigador (Semanas 3–5)
- [ ] Tools de threat intel (empezar con fuente offline/local; API real como opcional).
- [ ] Extracción y correlación de IOCs.
- [ ] Mapeo ATT&CK (portar del triage agent).
- [ ] Generación de hipótesis con nivel de confianza.
- **Criterio de salida:** para un incidente de phishing con IOC conocido, produce investigación con técnica ATT&CK correcta y evidencia citada.

### Fase 3 — Agente de Respuesta + Orquestador (Semanas 5–7)
- [ ] Biblioteca de playbooks base (3–5 tipos de incidente: phishing, brute force, malware, exfil).
- [ ] Lógica de sugerencia y priorización de pasos (NIST 800-61 como marco de referencia — además suma para Security+).
- [ ] Flags de aprobación humana por acción.
- [ ] Orquestador: máquina de estados simple del incidente (detected → investigating → response_suggested → closed).
- **Criterio de salida:** flujo e2e completo desde evento crudo hasta reporte final sin intervención manual.

### Fase 4 — Pulido y difusión (Semana 8)
- [ ] README completo en inglés (con GIF/demo del CLI).
- [ ] Reporte de ejemplo real en el repo (`examples/`).
- [ ] Tests e2e, GitHub Actions con lint + pytest.
- [ ] *Post LinkedIn #2 (ES/EN): demo del flujo completo con video corto.*
- [ ] Opcional: artículo técnico (dev.to o LinkedIn article) sobre "diseño de contratos entre agentes en seguridad".

---

## 5. Criterios de éxito

1. **Funcional:** de 15 escenarios de prueba, ≥12 producen un flujo e2e coherente (detección correcta, técnica ATT&CK razonable, playbook pertinente).
2. **Auditable:** cualquier reporte permite reconstruir por qué se tomó cada decisión.
3. **Portafolio:** README que un recruiter técnico entiende en 2 minutos; demo reproducible sin API keys de terceros (modo offline).
4. **Visibilidad:** mínimo 2 posts de LinkedIn publicados durante el desarrollo.

---

## 6. Riesgos y mitigaciones

| Riesgo | Impacto | Mitigación |
|---|---|---|
| Choque con estudio del Security+ | Retraso | Fases 3–4 son comprimibles; el proyecto es útil incluso si solo llega a Fase 2 con buen README |
| APIs de threat intel con límites o caídas | Demo frágil | Modo offline por defecto con dataset local; APIs como enhancement |
| Scope creep (tentación de ejecutar respuestas reales) | Nunca termina | v1 solo *sugiere*; ejecución queda documentada como roadmap v2 |
| Los agentes "alucinan" IOCs o técnicas | Credibilidad | Validación Pydantic estricta + verificar técnicas ATT&CK contra el catálogo oficial antes de reportarlas |
| Costo de tokens en pruebas | Presupuesto | Cachear respuestas en tests; usar el modelo más económico para el detector y reservar el más capaz para investigación |

---

## 7. Roadmap v2 (documentar, no construir)

- Conector abstracto para SIEM (interfaz `AlertSource` con implementación Splunk/Sentinel de ejemplo).
- Ejecución supervisada de acciones (con confirmación humana obligatoria).
- Dashboard web mínimo para revisar incidentes.
- Métricas: tiempo medio de triage, tasa de falsos positivos escalados.
- Evaluación sistemática con el dataset GUIDE completo.

---

## 8. Relación con el resto del portafolio

| Proyecto | Qué demuestra |
|---|---|
| 1. SOC Triage Agent | Un agente, tarea acotada, salida estructurada |
| 2. (proyecto intermedio) | — |
| **3. SOAR Orchestrator** | **Multi-agente, orquestación, human-in-the-loop, flujo IR completo** |

Narrativa para entrevistas: "empecé automatizando triage de Tier 1, y luego escalé el diseño a un pipeline completo de respuesta a incidentes con agentes especializados". Esa progresión es exactamente el perfil de *AI agent architect* aplicado a blue team.
