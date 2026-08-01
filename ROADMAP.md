# Wireless — Objetivos y Roadmap (Claude + MCP tshark-remoto)

## Contexto

Servidor MCP `tshark-remoto` (`tshark_server.py`, FastMCP, 23 tools) corre en un host remoto Ubuntu (venv en `/home/usuario/mcp_tshark/mcp_env`). El prompt original ("Wireless Network Analyst Copilot") intentaba cubrir health checks, troubleshooting, auditoría WPA2/3, detección de ataques y forense a la vez, con un flujo rígido de pasos fijos (Paso 0 → bloques 1-5). A partir de ahora el análisis lo realiza Claude directamente sobre las tools del MCP — se descarta el término "copilot" para referirse al sistema.

**Objetivo redefinido (27/07/2026):** Claude centrado en **troubleshooting de cliente/RF**, no en auditoría de seguridad ni en un pipeline tipo SOC. Fuente única de datos: `tshark-remoto` (sin integración con la API Meraki, decisión explícita — se descartó combinarlas).

## Casos de uso prioritarios

1. **Fallos de autenticación** — a nivel de protocolo (EAPOL, 802.1X/RADIUS, RSN/PMF), explícitamente *no* problemas de credenciales.
2. **Fallos de roaming** — sticky clients, transición lenta o fallida entre APs.
3. **"WiFi lento" / interferencia RF** — saturación de canal, co-channel/adjacent-channel, retries.

Más un requisito transversal: **persistencia/histórico** entre sesiones (hoy no existe — solo se guardan PCAPs crudos, ningún resultado estructurado).

## Gaps identificados en `tshark_server.py` (revisión de código, no especulación)

| # | Caso de uso | Gap concreto |
|---|---|---|
| 1 | Auth | `capturar_eapol` no interpreta M1–M4 ni detecta retransmisión/timeout del handshake |
| 2 | Auth | Ningún decoder de IE RSN (ID 48) → AKM/cipher/PMF invisibles, causa típica de fallo silencioso |
| 3 | Auth | `reason_code`/`status_code` se devuelven en crudo, sin traducir a texto |
| 4 | Roaming | Nada une management+auth+assoc+data por cliente en una línea de tiempo — no se puede medir el hueco de roaming |
| 5 | Roaming | `analizar_ies_pcap` no decodifica 802.11k (RRM, ID 70), 802.11v (BTM, ID 127) ni 802.11r (Mobility Domain, ID 54) |
| 6 | Roaming | No hay detección de sticky client (RSSI del AP actual vs otros BSSID del mismo SSID visibles) |
| 7 | RF/lento | `wlan.fc.retry` no se captura en ninguna tool — falta el indicador más directo de interferencia |
| 8 | RF/lento | `survey_canales` vuelca `iw survey dump` en crudo, sin % de utilización ni ranking de canales |
| 9 | RF/lento | No se combina señal (dBm cliente) con ruido (survey) para obtener SNR real |
| 10 | RF/lento | No hay conteo de vecinos co-channel/adjacent-channel a partir de `escanear_redes`/beacons |
| 11 | Persistencia | No existe ningún resultado estructurado guardado — imposible comparar sesiones ("¿esto ya pasó antes?") |

## Fases

### Fase 1 — Fallos de autenticación (protocolo)
- Clasificar mensajes EAPOL M1/M2/M3/M4 a partir de `eapol.keydes.key_info` y detectar retransmisión/timeout por par (sa,da).
- Añadir `_decode_rsn_ie()` (AKM suites, pairwise/group cipher, MFPC/MFPR) e integrarlo en `analizar_ies_pcap`.
- Diccionario de reason/status codes 802.11 estándar aplicado en `capturar_autenticacion`/`capturar_asociacion`.
- (Opcional) tool nueva `diagnosticar_autenticacion(interfaz, cliente_mac)` que combine las tres piezas en un veredicto único.

### Fase 2 — Fallos de roaming
- Tool nueva `reconstruir_roaming(pcap_o_interfaz, cliente_mac)`: une eventos por MAC cliente y calcula el gap de roaming (ms entre última trama data en AP viejo y primera en AP nuevo).
- Decodificar IEs 802.11k/v/r en `analizar_ies_pcap` para confirmar soporte real AP+cliente de fast-roaming.
- Detección de sticky client comparando RSSI del AP asociado vs RSSI de otros BSSID del mismo SSID vistos en la misma ventana.

### Fase 3 — "WiFi lento" / interferencia RF
- Añadir `wlan.fc.retry` a las capturas relevantes y calcular % de retry.
- Extender `survey_canales` (o tool nueva) para calcular utilización % (busy/active time) y ranking de canales en vez de volcar texto crudo.
- Combinar señal + ruido → SNR real por canal/cliente.
- Contar BSSID vecinos co-channel/adjacent-channel a partir de `escanear_redes`.

### Fase 4 — Persistencia / histórico
- Definir dónde vive el histórico: **pendiente de decidir** — en el servidor remoto (`~/mcp_tshark/historial/`, cerca de los PCAPs) vs en este repo (`Wireless/history/`, versionado en git). Se recomienda servidor remoto + tool `listar_historial()`/`comparar_historial()` para que Claude lo consulte, ya que el histórico crece con cada sesión real y no tiene sentido commitear cada resultado.
- Tool `guardar_resultado_sesion(...)` que cada troubleshooting invoque al final: JSON con fecha, caso de uso, interfaz/canal, métricas clave, conclusión, acción recomendada.
- `baselines.md` con umbrales por defecto (RSSI, retry%, utilización) contra los que juzgar "bien/mal" — a validar con el usuario antes de fijarlos como default.

## Ejecución

- Fases secuenciales. Dentro de cada fase, las tareas independientes (p.ej. Fase 1: decoder RSN vs. tabla de reason codes) se implementan en paralelo con subagentes.
- Cada fase se valida contra el servidor `tshark-remoto` real antes de pasar a la siguiente — lección aplicada del proyecto Wazuh: no fiarse de una implementación sin confirmarla contra tráfico real.
