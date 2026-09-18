# Wireless — Objetivos y Roadmap (Claude + MCP tshark-remoto)

## Contexto

Servidor MCP `tshark-remoto` (`tshark_server.py`, FastMCP, 27 tools) corre en un host remoto Ubuntu (venv en `/home/usuario/mcp_tshark/mcp_env`). El prompt original ("Wireless Network Analyst Copilot") intentaba cubrir health checks, troubleshooting, auditoría WPA2/3, detección de ataques y forense a la vez, con un flujo rígido de pasos fijos (Paso 0 → bloques 1-5). A partir de ahora el análisis lo realiza Claude directamente sobre las tools del MCP — se descarta el término "copilot" para referirse al sistema.

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
| 5 | Roaming | ✅ **Cerrado (12/09/2026)** — `analizar_ies_pcap` ya decodifica 802.11k (RRM, ID 70), 802.11v (BTM, bit 19 del IE 127) y 802.11r (Mobility Domain, ID 54). Ver "Modernización de IEs" abajo |
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
- ✅ **Hecho (12/09/2026):** decodificar IEs 802.11k/v/r para confirmar soporte real de fast-roaming, tanto en el **AP** (`analizar_ies_pcap`, línea `Roam.:`) como en el **cliente** (`perfilar_cliente_pcap`, línea `Roaming:`). Con las dos mitades ya se puede responder "¿por qué este cliente no hace roaming?" sin captura adicional.
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

## Descifrado WPA / conectividad post-asociación (06/08/2026, fuera de fase)

Añadido a raíz de evaluar el paquete [wireshark-mcp](https://github.com/bx33661/Wireshark-MCP) e **descartarlo como dependencia** (arquitectura stdio/local incompatible con el servidor remoto por streamable-http; sus 51 tools son L3+/SOC, ámbito descartado en este proyecto; no cubre ninguno de los 11 gaps de arriba). La única capacidad suya que sí faltaba aquí era el descifrado WPA, implementada directamente sobre `tshark_server.py`.

Cubre el caso **"asocia pero no navega"**: hasta ahora no se veía nada por encima de 802.11, así que el troubleshooting se cortaba justo donde termina la Fase 1.

- Config: `WPA_PROFILE_DIR` = `~/mcp_tshark/wireshark_profile/` (0700), con `80211_keys` en formato UAT de Wireshark (0600). Se crea a mano en el host.
- `_cmd_tshark(descifrar)` construye el comando base con `env WIRESHARK_CONFIG_DIR=... tshark -o wlan.enable_decryption:TRUE`. **No** se usa `-o uat:80211_keys:...` a propósito: la línea de comandos es visible vía `ps` para todo el host, y la passphrase no debe estar ahí. Por el mismo motivo no hay tool para dar de alta claves — como parámetro quedarían escritas en la conversación y en los logs del cliente MCP.
- `leer_pcap(..., descifrar=False)`: nuevo parámetro, aplica a todos los modos.
- `estado_descifrado_wpa()`: verifica fichero, permisos, claves cargadas (tipo + SSID, material de clave enmascarado) y avisa de líneas mal formadas — importante porque **una sola línea inválida hace que tshark rechace la tabla entera** y el descifrado quede desactivado en silencio (comprobado).
- `diagnosticar_conectividad_cliente(pcap, cliente_mac)`: comprueba primero si el descifrado ha surtido efecto (EAPOL vistos / data cifrada / data descifrada) y, si sí, analiza DHCP (tipo traducido), ARP y DNS con veredicto. Es el equivalente post-asociación de `diagnosticar_autenticacion`.

**Validado contra el host real** (backup: `tshark_server.py.bak_20260806_203319`): sintaxis UAT aceptada por tshark 4.0.17 sólo con las comillas embebidas; lectura de `80211_keys` desde `WIRESHARK_CONFIG_DIR` confirmada (se probó con fichero corrupto para forzar el error de carga); passphrase ausente de la línea de comandos; validación de MAC y de ruta de PCAP; sin regresión en las tools existentes.

**Pendiente de validar end-to-end:** ningún PCAP del host contiene un 4-Way Handshake (el único de monitor, `captura_wlan1_20260724_210906.pcap`, tiene 21 data frames cifrados y 0 EAPOL), así que **el descifrado real no se ha probado nunca con tráfico**. Lo que sí quedó demostrado es que la tool lo detecta y lo dice en vez de devolver un resultado vacío engañoso. Para cerrarlo: configurar la PSK real y capturar una reconexión de un cliente en el canal del AP.

## Modernización de IEs y escaneo estructurado (12/09/2026, fuera de fase)

Trabajo derivado de adoptar [WLAN Pi](https://github.com/wlan-pi) como referencia. Cierra el gap #5 y adelanta parte de la Fase 2. Backup previo: `tshark_server.py.bak_20260912_144035`. El servidor pasa de **25 a 27 tools**.

**Fuente de especificación:** [`wlanpi-profiler/CAPABILITY_LOGIC.md`](https://github.com/WLAN-Pi/wlanpi-profiler/blob/main/CAPABILITY_LOGIC.md) (BSD-3-Clause), que da IE id + offset + bit de 40+ capacidades Wi-Fi 4→7 ya destilados de la norma.

### Qué se añadió

- **IEs nuevos en `_parse_ies`:** 6 (Supported Channels), 33 (Power Capability), 54 (→802.11r), 70 (→802.11k), 127 (Extended Caps → 802.11v bit 19), 244 (RSNX → SAE H2E), y los extendidos 59 (Wi-Fi 6E), 106 (EHT/Wi-Fi 7) y 107 (Multi-Link/MLO).
- **Detector de generación** hasta Wi-Fi 7. Antes topaba en Wi-Fi 6 y además llamaba "Wi-Fi 4" a cualquier AP sin HT (802.11a/b/g).
- **Tool nueva `perfilar_cliente_pcap`** — perfila al CLIENTE desde su Association Request (modo *pcap analysis* de profiler: pasivo y offline, sin fake AP ni hostapd). Incluye detección de MAC aleatorizada y OUI→fabricante vía `/usr/share/ieee-data/oui.txt`.
- **Tool nueva `escanear_a_pcap`** — escaneo con [`scandump`](https://github.com/WLAN-Pi/scandump) (netlink → PCAP con radiotap+beacons). **No necesita modo monitor**: corre sobre `wlan0` managed y barre todas las bandas de una pasada, así que esquiva por completo el hallazgo abierto de `activar_modo_monitor(metodo="airmon")`. Instalado en `/usr/local/bin/scandump` con `CAP_NET_ADMIN`, no con sudo.
- **`escanear_ssid`** usa scandump si está disponible (seguridad derivada del IE RSN real) y cae automáticamente a `iw scan` si no. Filtro de SSID unificado a subcadena insensible a mayúsculas.
- **Capa estructurada** (`_recolectar_aps_pcap`): el análisis de beacons produce un dict antes de renderizarse a texto. Es el punto de enganche para la Fase 4 — no hay que re-parsear prosa para persistir resultados.

### Bugs corregidos (todos preexistentes, encontrados al validar)

| Dónde | Bug | Impacto |
|---|---|---|
| `_decode_he_capabilities` | SU/MU beamforming se leía de los bits 48/49/50 del PHY; en la norma son **B31/B32/B33** | Valores erróneos en **los 4 APs con HE** del entorno de prueba |
| `_decode_he_capabilities` | El bit etiquetado `bw_support_le_80mhz` era B1 = *40 MHz en 2.4 GHz*, banda equivocada | Ancho de canal mal reportado; ahora se exponen los 4 bits reales del Channel Width Set |
| `_decode_he_capabilities` | Exigía ≥22 bytes, pero un IE HE mínimo válido son 21 (6+11+4) | Descartaba IEs HE legítimos |
| `_decode_ht_capabilities` | Contaba streams sólo si el octeto era exactamente `0xFF` | `nss = 0` en radios con MCS set parcial |
| `escanear_ssid` (camino `iw`) | La línea del IE **`BSS Load:`** se tomaba por el inicio de un BSS nuevo | Red fantasma **y truncaba el registro del AP que se estaba parseando** |
| `escanear_ssid` | No deduplicaba por BSSID | `iw scan` lista BSS repetidos de caché → recuento inflado (46 "redes" para 23 BSSIDs) |

### Validación contra tráfico real (12/09/2026)

Entorno: `wlan1` monitor en canal 6, 1200 beacons (`valida_ws1_beacons_ch6.pcap`, conservado como evidencia). Contraste independiente contra la disección de Wireshark **sobre el mismo pcap**.

- **Wi-Fi 7 confirmado en vivo:** dos APs (`Livebox7-XXXX-WiFi7` del entorno, SSID anonimizado) con Ext Tags 106+107. tshark corrobora `35,36,39,38,107,108,106`. Antes se reportaban como Wi-Fi 6.
- **802.11k/v y RSNX:** `wlan.extcap.b19 = 1` y `wlan.rsnx.sae_hash_to_element = 1` coinciden con lo decodificado; tag 54 ausente → `802.11r=NO`, correcto.
- **Fix de beamforming:** cambió el resultado en los 4 APs con HE, y los valores nuevos coinciden **exactamente** con Wireshark (`38:91:…:8b` → 1/1/0; `60:8d:…:f4` → 1/1/1). Los antiguos no coincidían en ninguno.
- **MLO (ext 107):** **tshark 4.0.17 no disecciona este IE**, así que se verificó a mano sobre los bytes crudos. El cálculo de offset variable del Common Info (mapa de presencia `011011` → EML en offset 11, no 9) sale correcto: MLD MAC `1a:91:…:8b` (anonimizada), EMLSR=True, max enlaces=3. **Nuestro decoder lee algo que el tshark instalado no.**
- **`perfilar_cliente_pcap`:** validado sobre una captura con 2 Association Requests reales. Cliente con MAC aleatorizada, Wi-Fi 6, 2 streams, VHT 160 MHz, 11k+11v sin 11r, WPA2-PSK sin PMF. Potencia TX −7/20 dBm y todos los flags coinciden con Wireshark campo a campo.
- **scandump:** compila limpio en aarch64; 21-24 APs de todas las bandas en una pasada frente a 6 de un solo canal por monitor. Fallback probado forzando la rama `iw scan`: **100% de solape de BSSIDs entre ambos caminos** (22/22) tras corregir los dos bugs del parser.
- **Refactor de la capa estructurada:** salida **byte a byte idéntica** antes y después (11719 chars, `diff` vacío).
- **WS4a** (veredicto de auth) y los decoders: 45 + 31 comprobaciones sintéticas, todas pasan.

### No validable en este hardware

- **IE ext 59 (HE 6 GHz Band Capabilities):** ningún radio del host opera en 6 GHz (`wlan0`/`wlan1` son 2.4 + 5 GHz), así que sólo está cubierto por vector sintético. Se anota igual que el descifrado WPA.
- El campo `mcs15_support` / `eht_dup_mcs14_6ghz` del IE EHT no se ejerció: los APs del entorno emiten un EHT de 9 bytes, por debajo del umbral, y el decoder degrada correctamente omitiéndolos.
- `fijar_canal` **no soporta 6 GHz** y su docstring ya no lo promete: usa `iw set channel`, que no puede desambiguar un canal de 6 GHz (haría falta `iw set freq`). Es irrelevante mientras el hardware no tenga radio de 6 GHz.

## Ejecución

- Fases secuenciales. Dentro de cada fase, las tareas independientes (p.ej. Fase 1: decoder RSN vs. tabla de reason codes) se implementan en paralelo con subagentes.
- Cada fase se valida contra el servidor `tshark-remoto` real antes de pasar a la siguiente — lección aplicada del proyecto Wazuh: no fiarse de una implementación sin confirmarla contra tráfico real.

## Referencias externas

- [WLAN Pi](https://github.com/wlan-pi) — proyecto open-source de hardware/software para troubleshooting WiFi (captura, análisis 802.11, herramientas de RF). Referencia de dominio para el enfoque de diagnóstico de cliente/RF de este proyecto.
  - [`wlanpi-profiler/CAPABILITY_LOGIC.md`](https://github.com/WLAN-Pi/wlanpi-profiler/blob/main/CAPABILITY_LOGIC.md) (BSD-3-Clause) — especificación IE id + offset + bit de 40+ capacidades Wi-Fi 4→7. **Usada como fuente** para los decoders de 802.11k/r/v, RSNX, EHT y MLO.
  - [`wlanpi-profiler`](https://github.com/WLAN-Pi/wlanpi-profiler) — su modo *pcap analysis* (pasivo, offline) es el patrón de `perfilar_cliente_pcap`. Su modo fake-AP/hostapd queda **fuera de alcance**: es activo, y este proyecto es de diagnóstico pasivo.
  - [`scandump`](https://github.com/WLAN-Pi/scandump) (BSD-3-Clause) — escaneo netlink → PCAP. **Integrado** en `escanear_a_pcap` y `escanear_ssid`.
  - [`wlanpi-mcp`](https://github.com/WLAN-Pi/wlanpi-mcp) — servidor MCP on-device de WLAN Pi. **No se adopta**: envuelve la API REST de `wlanpi-core` y requiere la imagen de WLAN Pi OS, mientras que este host es una Raspberry Pi genérica que además comparte `eth0` con el laboratorio Wazuh. Útil como referencia de diseño de tools.
