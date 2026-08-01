# Wireless — Objetivos y Roadmap (Claude + MCP tshark-remoto)

## Contexto

Servidor MCP `tshark-remoto` (`tshark_server.py`, FastMCP, 23 tools) corre en un host remoto Ubuntu (venv en `/home/usuario/mcp_tshark/mcp_env`). El prompt original ("Wireless Network Analyst Copilot") intentaba cubrir health checks, troubleshooting, auditoría WPA2/3, detección de ataques y forense a la vez, con un flujo rígido de pasos fijos (Paso 0 → bloques 1-5). A partir de ahora el análisis lo realiza Claude directamente sobre las tools del MCP — se descarta el término "copilot" para referirse al sistema.

**Objetivo redefinido (27/07/2026):** Claude centrado en **troubleshooting de cliente/RF**, no en auditoría de seguridad ni en un pipeline tipo SOC. Fuente única de datos: `tshark-remoto` (sin integración con la API Meraki, decisión explícita — se descartó combinarlas).

## Casos de uso prioritarios

1. **Fallos de autenticación** — a nivel de protocolo (EAPOL, 802.1X/RADIUS, RSN/PMF), explícitamente *no* problemas de credenciales.
2. **Fallos de roaming** — sticky clients, transición lenta o fallida entre APs.
3. **"WiFi lento" / interferencia RF** — saturación de canal, co-channel/adjacent-channel, retries.

Más un requisito transversal: **persistencia/histórico** entre sesiones (hoy no existe — solo se guardan PCAPs crudos, ningún resultado estructurado).

## Adaptadores disponibles (verificado en vivo, 01/08/2026)

Inventario real del host (`listar_interfaces` + `capacidades_phy`), no asunciones del prompt original:

| Interfaz | Phy | Modo monitor | Bandas | Notas |
|---|---|---|---|---|
| `wlan1` | phy1 | Sí | 2.4 + 5 GHz (HT/VHT) | Único radio monitor-capable. `#channels <= 1` en sus combos válidos → **no puede escuchar 2 canales a la vez**, ni con interfaces virtuales. |
| `wlan0` | phy0 | No | 2.4 + 5 GHz (HT/VHT single-stream) | Solo managed: escaneo (`escanear_redes`/`escanear_ssid`) o asociación real. |
| `eth0` | — | — (cableada) | — | SPAN port del mismo host (Raspberry Pi, usuario `usuario`), compartido con el laboratorio Wazuh-ThreatHunting. Fuera de alcance para troubleshooting WiFi — no confundir. |

**Implicación para el diseño:** no hay verdadero multi-canal simultáneo sin un segundo adaptador USB monitor-capable (no presente hoy). Lo que sí es viable con el hardware actual es **paralelismo monitor + managed**: `wlan1` en modo monitor capturando tramas crudas mientras `wlan0` se mantiene en managed para verificar el lado "real" de la conexión (RSSI/latencia tal como lo ve un cliente asociado, o un escaneo de vecinos sin interrumpir la captura). Se aplica en Fase 1 y Fase 3 más abajo.

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
- (Opcional, usa `wlan0` en paralelo) si el caso lo permite, asociar `wlan0` en managed al mismo SSID para confirmar si el fallo es reproducible desde un cliente real mientras `wlan1` captura en monitor — no siempre aplicable (depende de credenciales disponibles), evaluar caso a caso.

### Fase 2 — Fallos de roaming
- Tool nueva `reconstruir_roaming(pcap_o_interfaz, cliente_mac)`: une eventos por MAC cliente y calcula el gap de roaming (ms entre última trama data en AP viejo y primera en AP nuevo).
- Decodificar IEs 802.11k/v/r en `analizar_ies_pcap` para confirmar soporte real AP+cliente de fast-roaming.
- Detección de sticky client comparando RSSI del AP asociado vs RSSI de otros BSSID del mismo SSID vistos en la misma ventana.
- **Limitación de hardware a tener en cuenta:** `wlan1` es un único radio (un canal a la vez), así que si el AP origen y destino están en canales distintos no se puede capturar el roam completo en tiempo real con un solo pase — la reconstrucción tendrá que apoyarse en `capturar_a_pcap` de más duración en el canal más probable, o en analizar el evento a posteriori vía beacons/probes ya vistos, no en captura simultánea de ambos canales.

### Fase 3 — "WiFi lento" / interferencia RF
- Añadir `wlan.fc.retry` a las capturas relevantes y calcular % de retry.
- Extender `survey_canales` (o tool nueva) para calcular utilización % (busy/active time) y ranking de canales en vez de volcar texto crudo.
- Combinar señal + ruido → SNR real por canal/cliente.
- Contar BSSID vecinos co-channel/adjacent-channel a partir de `escanear_redes`.
- Cruzar el SNR calculado desde `wlan1` (monitor) con la calidad de enlace real reportada por `wlan0` (managed, `iw dev wlan0 link`: signal, bitrate) como referencia de "lo que ve un cliente real" en paralelo a la captura cruda.

### Fase 4 — Persistencia / histórico
- Definir dónde vive el histórico: **pendiente de decidir** — en el servidor remoto (`~/mcp_tshark/historial/`, cerca de los PCAPs) vs en este repo (`Wireless/history/`, versionado en git). Se recomienda servidor remoto + tool `listar_historial()`/`comparar_historial()` para que Claude lo consulte, ya que el histórico crece con cada sesión real y no tiene sentido commitear cada resultado.
- Tool `guardar_resultado_sesion(...)` que cada troubleshooting invoque al final: JSON con fecha, caso de uso, interfaz/canal, métricas clave, conclusión, acción recomendada.
- `baselines.md` con umbrales por defecto (RSSI, retry%, utilización) contra los que juzgar "bien/mal" — a validar con el usuario antes de fijarlos como default.

## Validación Fase 1 (01/08/2026, contra la Raspberry Pi real)

Desplegado en `/home/usuario/mcp_tshark/tshark_server.py` y validado en vivo (backup previo: `tshark_server.py.bak_20260801_174340`).

**Bugs preexistentes encontrados y corregidos durante la validación (bloqueaban todo el roadmap, no solo la Fase 1):**
1. `activar_modo_monitor(metodo="airmon")` no hacia `return salida` → siempre devolvia `None` y fallaba con un error de validacion Pydantic.
2. `activar_modo_monitor(metodo="airmon")` ejecutaba `airmon-ng stop {interfaz}` en vez de `airmon-ng start {interfaz}` (copy-paste de `desactivar_modo_monitor`) → el modo monitor nunca se activaba realmente.
3. Tras crear el VIF monitor, el codigo hacia `ip link set {iface_base} up` (dejando la interfaz managed residual levantada) en vez de bajarla → `fijar_canal` fallaba con "Device or resource busy". Corregido a `down`.
4. `capturar_eapol` usaba los campos `eapol.type` / `eapol.keydes.key_info`, que no existen en tshark 4.0.17 de este host (dissector real: `wlan_rsna_eapol.keydes.*`, que ademas ya trae `msgnr` con el numero de mensaje M1-M4 calculado). Corregido, y `_analizar_eapol_capturado` ahora usa `msgnr` como fuente primaria y el decodificador de bits de `key_info` como respaldo (util para G1/G2, que `msgnr` no cubre).

**Validado con datos reales:**
- Decoder RSN (`analizar_ies_pcap` sobre una captura real de `wlan1`): AKM, cipher y PMF correctos contra 2 AP reales del entorno (WPA2-Personal, CCMP-128, PMF no soportado).
- `activar_modo_monitor` → `fijar_canal` → `desactivar_modo_monitor` en `wlan1`/`wlan1mon`, ciclo completo en vivo tras los fixes 1-3.
- Nombres de campo de `capturar_autenticacion`/`capturar_asociacion` (`wlan.fixed.reason_code`, `wlan.fixed.status_code`, `wlan.fixed.auth.alg`) confirmados validos en tshark 4.0.17.

**No se pudo validar con trafico real (no es un fallo del codigo, es ausencia de eventos):** ni el PCAP historico ni la ventana de captura en vivo contenian frames de auth/deauth/disassoc/EAPOL — el entorno no tuvo esos eventos durante la prueba. La clasificacion M1-M4/G1-G2 y la traduccion de reason/status code estan revisadas contra el estandar 802.11 y corren sin errores de tshark, pero falta una pasada con un evento real (una asociacion o un deauth real) para confirmar el resultado end-to-end. No se ha forzado trafico (deauth activo) por no ser una accion pasiva/autorizada para este entorno.

**Hallazgo adicional fuera de alcance de esta fase (pendiente, no bloqueante):** `leer_pcap(modo="wlan")` usa `-z wlan,stat`, invalido en tshark 4.0.17 (el nombre correcto seria `conv,wlan` o `endpoints,wlan`). No se ha corregido en esta pasada.

## Ejecución

- Fases secuenciales. Dentro de cada fase, las tareas independientes (p.ej. Fase 1: decoder RSN vs. tabla de reason codes) se implementan en paralelo con subagentes.
- Cada fase se valida contra el servidor `tshark-remoto` real antes de pasar a la siguiente — lección aplicada del proyecto Wazuh: no fiarse de una implementación sin confirmarla contra tráfico real.
