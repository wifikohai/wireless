# CLAUDE.md — Proyecto Wireless (MCP tshark-remoto)
> Contexto operacional para Claude. Leer al inicio de cada sesión.
> Mapa de estructura del repo: [`README.md`](README.md). Objetivos, fases y log de validación detallado: [`ROADMAP.md`](ROADMAP.md).

---

## 1. Contexto del proyecto

Servidor MCP `tshark-remoto` (`tshark_server.py`, FastMCP) que expone captura/análisis 802.11 (tshark/iw/scapy) sobre un adaptador WiFi en modo monitor, para troubleshooting real de cliente/RF sin ejecutar tshark a mano.

**Alcance:** troubleshooting de cliente/RF (auth, roaming, RF/interferencia, conectividad post-asociación). **No** es auditoría de seguridad ni pipeline SOC — decisión explícita, sin integración con la API Meraki. Fuente única de datos: `tshark-remoto`.

---

## 2. Infraestructura

| Componente | Valor |
|---|---|
| Host | Raspberry Pi, `usuario@10.10.1.142` (hostname `raspberrypi`) |
| Servicio | systemd `mcp-tshark.service` — FastMCP `streamable-http`, puerto 8000 (`/home/usuario/mcp_tshark/mcp_env`) |
| Interfaz de captura | `wlan1` (phy1) — **única con modo monitor**. `#channels <= 1`: no escucha 2 canales a la vez |
| Interfaz managed-only | `wlan0` (phy0) — solo escaneo/asociación real |
| `eth0` | SPAN port del mismo host, compartido con el laboratorio Wazuh-ThreatHunting. Fuera de alcance para WiFi — no confundir |
| NetworkManager | `wlan0`/`wlan1` **unmanaged** (confirmado con `nmcli device status`) → el modo monitor nunca lo toca. `eth0` **sí gestionado** ("Wired connection 1") — relevante, ver Hallazgos §4 |
| Sudo de `usuario` | `(ALL) NOPASSWD: ALL` (sin restricción) + lista específica heredada (`iw`, `airmon-ng`, `tshark`, `ip`, `systemctl restart NetworkManager`). Cualquier `sudo -n <lo que sea>` funciona sin contraseña |
| Directorio capturas | `/home/usuario/mcp_tshark/capturas` — `777`. Los `.pcap` los crea tshark como root pero el propio código hace `chmod 644` tras cada captura |
| Descifrado WPA | Desactivado por defecto. Claves en `~/mcp_tshark/wireshark_profile/80211_keys` (formato UAT Wireshark, 0600), creadas a mano en el host — nunca vía parámetro de tool (quedarían en logs/conversación) |
| Despliegue | Manual: editar local → `scp` → validar sintaxis (`ast.parse`) → `mv` → `sudo systemctl restart mcp-tshark.service`, con backup previo (`tshark_server.py.bak_<timestamp>`). Ver comandos exactos en README §Despliegue |

---

## 3. Herramientas expuestas (27 — verificado 12/09/2026 contra el código fuente real en el host, no contra documentación)

### Interfaces y capacidades (3)
`listar_interfaces`, `info_interfaz`, `capacidades_phy`

### Modo monitor y canal (3)
`activar_modo_monitor` (⚠️ ver §4), `desactivar_modo_monitor`, `fijar_canal`

### Escaneo y survey (4)
`survey_canales`, `escanear_redes`, `escanear_ssid`, `escanear_a_pcap`

- `escanear_a_pcap(interfaz, frecuencias, pasivo, nombre)` — escanea con `scandump` (netlink → PCAP radiotap+beacons). **No necesita modo monitor**: va sobre `wlan0` managed y barre todas las bandas de una pasada, así que **esquiva el hallazgo abierto de §4**. Encadena con `analizar_ies_pcap`.
- `escanear_ssid` usa `scandump` si está instalado (seguridad desde el IE RSN real) y cae solo a `iw scan` si no. Filtro de SSID: subcadena, insensible a mayúsculas.

### Captura en tiempo real (9)
`capturar_beacons`, `capturar_probe_requests`, `capturar_autenticacion`, `capturar_asociacion`, `capturar_eapol`, `capturar_management`, `capturar_control`, `capturar_datos`, `estadisticas_wlan`

### PCAP (5)
`capturar_a_pcap`, `listar_pcaps`, `leer_pcap` (soporta `descifrar=True`), `analizar_ies_pcap`, `perfilar_cliente_pcap`

- `analizar_ies_pcap` — perfila el **AP** desde sus beacons: generación **hasta Wi-Fi 7** (EHT ext 106, MLO ext 107, 6E ext 59), roaming **802.11k/r/v**, RSN/AKM/PMF y RSNX/SAE-H2E. Por debajo produce un dict estructurado (`_recolectar_aps_pcap`) antes de renderizar texto — punto de enganche para la Fase 4.
- `perfilar_cliente_pcap(nombre, cliente_mac, max_clientes)` — perfila el **CLIENTE** desde su Association Request: generación, streams, anchos, bandas (IE 6), potencia TX (IE 33), 802.11k/r/v/w, seguridad pedida, detección de **MAC aleatorizada** y OUI→fabricante. Pasivo y offline; **no** usa fake AP. Necesita que la captura contenga la asociación.

### Diagnóstico combinado — **no cubiertas por el prompt de la skill `wireless-network-analyst`** (3)
- `diagnosticar_autenticacion(interfaz, paquetes)` — combina auth+EAPOL en una pasada y da **veredicto automático** (timeout 4-way, fallo 802.1X, timeout group key). Desde 12/09/2026 el veredicto se calcula sobre **reason codes numéricos (15/16/23) y hechos estructurados**, no buscando subcadenas en su propia prosa — antes, reescribir un literal de `_REASON_CODES` rompía el diagnóstico en silencio
- `diagnosticar_conectividad_cliente(nombre, cliente_mac)` — caso "asocia pero no navega": descifra WPA y revisa DHCP/ARP/DNS de un cliente sobre un PCAP. Complementa a `diagnosticar_autenticacion` (antes vs. después de la asociación)
- `estado_descifrado_wpa()` — verifica fichero/permisos/claves de descifrado sin revelar el material de clave

**Gap de documentación:** `SKILL.md` de `wireless-network-analyst` (que guía los health checks/troubleshooting en runtime) no menciona estas 3 tools ni las integra en sus flujos. Pendiente decidir si se actualiza la skill — encajarían bien en el bloque de troubleshooting de cliente, sobre todo `diagnosticar_autenticacion` por el veredicto directo.

**Dependencia opcional:** `escanear_a_pcap` necesita el binario `scandump` en `/usr/local/bin/scandump` (instalado 12/09/2026 con `CAP_NET_ADMIN`, no con sudo). Si faltara, `escanear_ssid` cae solo a `iw scan` y solo `escanear_a_pcap` deja de estar operativa. Instrucciones de build en README §Despliegue.

---

## 4. Hallazgo abierto (10/08/2026) — posible regresión en `activar_modo_monitor(metodo="airmon")`

`ROADMAP.md` (Validación Fase 1, 01/08/2026) da por corregidos y validados 3 bugs de `activar_modo_monitor(metodo="airmon")` (faltaba `return salida`, `airmon-ng stop` en vez de `start`, `ip link up` en vez de `down`). **Confirmado en el código fuente actual: los 3 fixes siguen desplegados** (revisado línea por línea el 10/08/2026).

Sin embargo, en sesión real de hoy, **dos intentos consecutivos con `metodo="airmon"` (sobre `wlan1` y `wlan0`) fallaron** con el mismo síntoma que los bugs "ya corregidos": error de validación Pydantic porque la tool devolvió `None` en vez de un string.

**Lo que sí se descartó:** no es que hayan vuelto los 3 bugs originales (el código está bien). No es un problema de `_run()` (siempre devuelve string, nunca `None`, revisado).

**Hipótesis no confirmada:** la rama `airmon` termina con `systemctl restart NetworkManager` (+ `sleep(8)`). `wlan0`/`wlan1` están `unmanaged`, así que ese restart no los toca — pero **`eth0` sí está gestionado por NetworkManager**, y se observó en estado `connecting (getting IP configuration)` durante esta misma investigación. Si `eth0` es la interfaz por la que corre la conexión `streamable-http` del MCP, un restart de NetworkManager podría cortar momentáneamente esa conexión a mitad de la llamada y explicar el `None`. **No verificado con logs del instante exacto del fallo** — se anota como hipótesis, no como causa confirmada.

**Workaround confirmado y usado con éxito repetidamente esta sesión:** `metodo="iw"` (no pasa por NetworkManager en absoluto, ciclo completo down→set monitor→up, verificado varias veces).

**Vía de escape añadida (12/09/2026):** para el caso concreto de *escanear*, ya no hace falta modo monitor en absoluto — `escanear_a_pcap` usa `scandump` sobre `wlan0` en managed y produce un PCAP analizable con `analizar_ies_pcap`. Eso saca a todo el flujo de escaneo del alcance de este hallazgo. La captura de tramas sí sigue necesitando monitor.

**Recomendación práctica hasta investigarlo a fondo:** preferir `metodo="iw"` sobre `airmon` al activar modo monitor. Si se confirma la hipótesis de NetworkManager, valorar quitar el paso `systemctl restart NetworkManager` de la rama `airmon` (parece un intento de limpiar el VIF managed residual, pero `iw` ya resuelve eso sin tocar NetworkManager) o excluir `eth0` de NetworkManager si no hace falta que lo gestione.

---

## 5. Pendiente

- Investigar y confirmar (o descartar) la hipótesis de §4 con logs del host en el momento exacto de un fallo `airmon`.
- Decidir si se actualiza `SKILL.md` de `wireless-network-analyst` para: (a) incluir las 3 tools de diagnóstico combinado, (b) incluir `perfilar_cliente_pcap` y `escanear_a_pcap`, (c) invertir la preferencia `airmon`→`iw` mientras dure el hallazgo de §4.
- ~~Corregir el "23 tools" desactualizado en la cabecera de `ROADMAP.md`~~ — hecho 12/09/2026 (dice 27).
- Validar el IE ext 59 (HE 6 GHz) cuando haya hardware de 6 GHz: hoy sólo está cubierto por vector sintético, porque ni `wlan0` ni `wlan1` operan en esa banda.
- `analizar_ies_pcap` no decodifica el Ext Tag **108 (EHT Operation)**, que sí está presente en los beacons Wi-Fi 7 del entorno. Gap conocido y acotado: no impide detectar Wi-Fi 7 (eso lo da el 106).
- Resto de pendientes de producto (Fases 2-4: roaming, RF/interferencia, persistencia/histórico) — ver `ROADMAP.md`, no se repiten aquí.
