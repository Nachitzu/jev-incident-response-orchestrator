<h1 align="center">AI Incident Response Orchestrator</h1>

<p align="center"><strong>🚧 Trabajo en progreso</strong></p>

<p align="center">
  <em>Un pipeline multi-agente estilo SOAR que lleva un evento de seguridad crudo
  por todo el ciclo de vida del incidente: <b>detectar → investigar → responder</b>,
  con contratos estrictos y human-in-the-loop por diseño.</em>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white">
  <img alt="Pydantic" src="https://img.shields.io/badge/contracts-pydantic%20v2-E92063">
  <img alt="Tests" src="https://img.shields.io/badge/tests-offline%20pytest-0A9EDC">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue">
</p>

<p align="center"><a href="README.md">English</a> · Español</p>

---

## Resumen

Un agente de triage Tier 1 clasifica una alerta. Un SOC hace más: correlaciona
eventos en un incidente, lo investiga contra threat intelligence y MITRE ATT&CK,
y propone un playbook de respuesta, escalando a un humano cuando una acción pueda
tener impacto.

Este proyecto modela ese ciclo con tres agentes especializados coordinados por un
orquestador que controla la máquina de estados y produce un log de decisiones
auditable. Es la evolución del
[SOC Triage Agent](https://github.com/Nachitzu/ai-soc-triage-agent): un agente se
convirtió en un pipeline de tres.

> **Principio de diseño:** los agentes nunca intercambian texto libre. Cada
> frontera (`RawEvent`, `Incident`, `Investigation`, `ResponsePlan`, `CaseReport`)
> es un contrato Pydantic validado. Las reglas de seguridad las impone el schema,
> no la convención.

**Alcance actual:** el sistema sugiere un playbook y genera un reporte. Nunca
ejecuta acciones contra un host. La arquitectura y las interfaces pueden cambiar
mientras el proyecto avanza hacia v1.

## Características principales

- Detección, investigación y respuesta como etapas separadas.
- Contratos Pydantic v2 entre todas las etapas.
- Threat intelligence offline-first con reputación local y catálogo MITRE ATT&CK.
- Playbooks alineados con NIST SP 800-61.
- Human-in-the-loop obligatorio para acciones destructivas o de alto impacto.
- Audit log en reportes Markdown y JSON.
- Dos modos de ejecución: API de Anthropic o consola de Claude Code sin API key.
- Pruebas offline con clientes LLM simulados.

## Arquitectura

```text
  Eventos crudos (data/scenarios/*.json)
        │  RawEvent[]
        ▼
  ┌──────────────┐   descarta falsos positivos obvios
  │ DetectorAgent │──────────────────────────────► closed_false_positive
  └──────┬───────┘   Incident
         ▼
  ┌──────────────────┐◄──► ThreatIntel offline-first
  │ InvestigatorAgent │      reputación local + catálogo ATT&CK
  └──────┬───────────┘   Investigation
         ▼
  ┌──────────────┐◄──► Biblioteca de playbooks JSON
  │ ResponderAgent│   ResponsePlan + aprobación humana
  └──────┬───────┘
         ▼
  ┌───────────────────────────────────────────────┐
  │ Orquestador: máquina de estados + audit log   │
  │ detected → investigating → response_suggested │
  │          → closed / escalated_to_human         │
  └──────┬────────────────────────────────────────┘
         ▼
  CaseReport (Markdown + JSON)
```

Consulta [`docs/architecture.md`](docs/architecture.md) para el desglose de
componentes, estados y decisiones de diseño.

## Requisitos

- Python 3.11 o superior.
- [`uv`](https://docs.astral.sh/uv/) para instalar dependencias y ejecutar
  comandos.
- Una `ANTHROPIC_API_KEY` para el modo API.
- Una `TYPESAFE_API_KEY` es opcional; sin ella, Jev puede funcionar en modo
  deshabilitado según la configuración.

La threat intelligence incluida funciona sin claves de terceros. La clave
`ABUSEIPDB_API_KEY` es opcional y solo habilita consultas de reputación en vivo.

## Instalación

```bash
uv sync --extra dev
```

Para configurar variables localmente, copia [`.env.example`](.env.example) a
`.env` y carga sus valores en tu shell. El proyecto no carga automáticamente
archivos `.env`.

## Inicio rápido

### Comandos del pipeline

```bash
# Listar escenarios incluidos
uv run soar-orchestrator scenarios

# Listar playbooks disponibles
uv run soar-orchestrator playbooks

# Ejecutar un escenario y escribir reports/<incident_id>.md y .json
uv run soar-orchestrator run data/scenarios/phishing-01.json
```

El modo API requiere `ANTHROPIC_API_KEY`. Los modelos pueden sobrescribirse por
etapa con `--detector-model`, `--investigator-model` y `--responder-model`, o de
forma global con `SOAR_MODEL`. Para no escribir archivos usa `--no-report`; para
cambiar el destino usa `--out reports/`.

Ejemplo de resumen:

```text
case phishing-01: escalated_to_human
  incident   : Credential-harvesting phishing against a finance user
  category   : phishing / HIGH (confidence 0.86)
  ATT&CK     : T1566.002, T1204.001
  kill chain : delivery
  plan       : 5 step(s), 3 needing human approval
  report     : reports/phishing-01.md  |  reports/phishing-01.json
```

### Modo consola de Claude Code, sin API key

En una sesión de [Claude Code](https://claude.com/claude-code) dentro del repo,
la sesión viva hace el razonamiento y Python ejecuta solo la parte determinista:
validación, threat intelligence offline, verificación ATT&CK, selección de
playbooks y renderizado.

```text
/soar-run data/scenarios/phishing-01.json
```

También están disponibles las etapas individuales:

```text
/soar-detect data/scenarios/phishing-01.json
/soar-investigate path/to/incident.json
/soar-respond path/to/incident.json path/to/investigation.json
```

Los comandos viven en `.claude/commands/` y usan los mismos prompts compartidos
en [`src/orchestrator/prompts/`](src/orchestrator/prompts/). La herramienta
determinista puede usarse directamente:

```bash
uv run soar-tool intel 45.133.1.77 --type ip
uv run soar-tool attack verify T1566
uv run soar-tool attack search phishing
uv run soar-tool playbook phishing
uv run soar-tool validate --schema incident --in incident.json
uv run soar-tool report --case case.json --out reports/
```

`soar-tool` no necesita API key y emite JSON en stdout.

## Contratos y estados

| Schema | Producido por | Significado |
|---|---|---|
| `RawEvent` | Ingesta | Evento crudo de SIEM, EDR, firewall o email |
| `DetectionResult` | DetectorAgent | Decisión de escalar y el `Incident` resultante |
| `Incident` | DetectorAgent | Incidente categorizado o descarte registrado |
| `Investigation` | InvestigatorAgent | IOCs enriquecidos, hipótesis y técnicas ATT&CK verificadas |
| `ResponsePlan` | ResponderAgent | Pasos priorizados con flags de aprobación |
| `CaseReport` | Orquestador | Caso completo y audit log en JSON y Markdown |

El flujo normal es:

```text
DETECTED → INVESTIGATING → RESPONSE_SUGGESTED
                         ├→ CLOSED_RESOLVED_SUGGESTED
                         └→ ESCALATED_TO_HUMAN
```

Un falso positivo termina en `CLOSED_FALSE_POSITIVE`. Las transiciones inválidas
fallan explícitamente.

## Barreras de seguridad

| Barrera | Implementación | Qué evita |
|---|---|---|
| Validación y reintento | `_llm.complete_validated()` | Que una respuesta inválida continúe aguas abajo |
| Verificación ATT&CK | `investigator_agent.py` | Que una técnica inventada llegue al reporte |
| Human-in-the-loop | Validadores de `PlaybookStep` y `ResponsePlan` | Acciones destructivas sin aprobación |
| Trazado de identidad | `extra_check` de cada agente | Mezclar resultados de incidentes distintos |
| Encuadre anti-inyección | Bloques `<events>` y `<incident>` | Tratar datos de logs como instrucciones |
| Intel offline-first | `tools/intel.py` | Depender de una API externa para el caso feliz |

El diseño también incorpora patrones de Jev: screening temprano de falsos
positivos, verificaciones calibradas de grounding y puntuación de blast radius.
La configuración relevante incluye `SOAR_JEV_MODE`, `SOAR_FP_NOUL_THRESHOLD` y
`SOAR_HITL_CONFIDENCE_MIN`; consulta [`.env.example`](.env.example).

## Estructura del proyecto

```text
src/orchestrator/
├── agents/       # Detector, Investigator y Responder
├── prompts/      # Prompts compartidos por ambos modos
├── schemas/      # Contratos Pydantic
├── tools/        # Threat intel, ATT&CK y playbooks
├── reporting/    # Renderizado Markdown/JSON
├── cli.py        # soar-orchestrator
├── toolcli.py    # soar-tool
└── orchestrator.py
data/             # Escenarios, inteligencia local y playbooks
docs/             # Documentación de arquitectura
tests/            # Tests unitarios y de integración offline
```

## Estado actual

El flujo principal, los contratos, la CLI, los playbooks locales, el modo consola
y la suite de tests offline ya están implementados. El repositorio sigue en
desarrollo activo: faltan integraciones operativas, persistencia y ejecución
controlada de acciones reales.

## Desarrollo y tests

```bash
uv sync --extra dev
uv run pytest -q
```

La suite está diseñada para no tocar la red ni consumir APIs durante las pruebas.
Los clientes LLM son inyectables y se simulan en los tests.

## Limitaciones y roadmap

Todavía no forman parte del proyecto:

- Ejecución real de contención, erradicación o recuperación contra hosts.
- Integración directa con SIEM/EDR comerciales.
- Almacén persistente de casos o correlación multi-caso.
- UI web.
- Threat intelligence en vivo como ruta predeterminada.

Estas capacidades quedan para v2 porque aumentan significativamente el radio de
daño y requieren controles operativos adicionales.

## Autor y licencia

**Nachitzu** — Blue team y arquitectura de agentes de IA. Consulta también el
[SOC Triage Agent](https://github.com/Nachitzu/ai-soc-triage-agent).

MIT — consulta [`LICENSE`](LICENSE).
