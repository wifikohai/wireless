# CLAUDE.md — Proyecto Wireless (MCP tshark-remoto)
> Contexto operacional para Claude. Leer al inicio de cada sesión.
> Mapa de estructura del repo: [`README.md`](README.md). Objetivos, fases y log de validación detallado: [`ROADMAP.md`](ROADMAP.md). Catálogo de problemas ya investigados y sus resoluciones/workarounds: skill de proyecto `wireless-troubleshooting` (`.claude/skills/wireless-troubleshooting/SKILL.md`).

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
| Interfaz de captura | `wlan1` (phy1, adaptador USB con chipset MediaTek MT7612U) — **única con modo monitor**. `#channels <= 1`: no escucha 2 canales a la vez |
| Interfaz managed-only | `wlan0` (phy0, WiFi integrado de la Raspberry Pi) — no soporta modo monitor; solo escaneo/asociación real |
| `eth0` | Puerto SPAN de captura pasiva para el laboratorio Wazuh-ThreatHunting del mismo host — sin IP propia, fuera de alcance para WiFi. No confundir con `eth1` |
| `eth1` | Interfaz cableada real con IP de este host (`connected`, NetworkManager) — probablemente la que lleva la conexión `streamable-http` de este MCP hacia el cliente |
| NetworkManager | `wlan0`/`wlan1` **unmanaged** (confirmado con `nmcli device status`) → el modo monitor nunca lo toca. `eth1` sí gestionado y conectado — relevante para el problema de `activar_modo_monitor(metodo="airmon")`, ver skill `wireless-troubleshooting` |
| Sudo de `usuario` | `(ALL) NOPASSWD: ALL` (sin restricción) + lista específica heredada (`iw`, `airmon-ng`, `tshark`, `ip`, `systemctl restart NetworkManager`). Cualquier `sudo -n <lo que sea>` funciona sin contraseña |
| Directorio capturas | `/home/usuario/mcp_tshark/capturas` — `777`. Los `.pcap` los crea tshark como root pero el propio código hace `chmod 644` tras cada captura |
| Descifrado WPA | Desactivado por defecto. Claves en `~/mcp_tshark/wireshark_profile/80211_keys` (formato UAT Wireshark, 0600), creadas a mano en el host — nunca vía parámetro de tool (quedarían en logs/conversación) |
| Despliegue | Manual: editar local → `scp` → validar sintaxis (`ast.parse`) → `mv` → `sudo systemctl restart mcp-tshark.service`, con backup previo (`tshark_server.py.bak_<timestamp>`). Ver comandos exactos en README §Despliegue |

---

## 3. Herramientas expuestas (27 — verificado 12/09/2026 contra el código fuente real en el host, no contra documentación)

### Interfaces y capacidades (3)
`listar_interfaces`, `info_interfaz`, `capacidades_phy`

### Modo monitor y canal (3)
`activar_modo_monitor` (⚠️ prefiere `metodo="iw"`, ver skill `wireless-troubleshooting`), `desactivar_modo_monitor`, `fijar_canal`

### Escaneo y survey (4)
`survey_canales`, `escanear_redes`, `escanear_ssid`, `escanear_a_pcap`

- `escanear_a_pcap(interfaz, frecuencias, pasivo, nombre)` — escanea con `scandump` (netlink → PCAP radiotap+beacons). **No necesita modo monitor**: va sobre `wlan0` managed y barre todas las bandas de una pasada, así que **esquiva por completo el problema de `activar_modo_monitor`**. Encadena con `analizar_ies_pcap`.
- `escanear_ssid` usa `scandump` si está instalado (seguridad desde el IE RSN real) y cae solo a `iw scan` si no. Filtro de SSID: subcadena, insensible a mayúsculas.

### Captura en tiempo real (9)
`capturar_beacons`, `capturar_probe_requests`, `capturar_autenticacion`, `capturar_asociacion`, `capturar_eapol`, `capturar_management`, `capturar_control`, `capturar_datos`, `estadisticas_wlan`

### PCAP (5)
`capturar_a_pcap`, `listar_pcaps`, `leer_pcap` (soporta `descifrar=True`), `analizar_ies_pcap`, `perfilar_cliente_pcap`

- `analizar_ies_pcap` — perfila el **AP** desde sus beacons: generación **hasta Wi-Fi 7** (EHT ext 106, MLO ext 107, 6E ext 59), roaming **802.11k/r/v**, RSN/AKM/PMF y RSNX/SAE-H2E. Por debajo produce un dict estructurado (`_recolectar_aps_pcap`) antes de renderizar texto — punto de enganche para la Fase 4.
- `perfilar_cliente_pcap(nombre, cliente_mac, max_clientes)` — perfila el **CLIENTE** desde su Association Request: generación, streams, anchos, bandas (IE 6), potencia TX (IE 33), 802.11k/r/v/w, seguridad pedida, detección de **MAC aleatorizada** y OUI→fabricante. Pasivo y offline; **no** usa fake AP. Necesita que la captura contenga la asociación.

### Diagnóstico combinado — **no cubiertas por el prompt de la skill `wireless-network-analyst`** (3)
- `diagnosticar_autenticacion(interfaz, paquetes)` — combina auth+EAPOL en una pasada y da **veredicto automático** (timeout 4-way, fallo 802.1X, timeout group key), calculado sobre reason codes numéricos y hechos estructurados, no sobre subcadenas de texto.
- `diagnosticar_conectividad_cliente(nombre, cliente_mac)` — caso "asocia pero no navega": descifra WPA y revisa DHCP/ARP/DNS de un cliente sobre un PCAP. Complementa a `diagnosticar_autenticacion` (antes vs. después de la asociación).
- `estado_descifrado_wpa()` — verifica fichero/permisos/claves de descifrado sin revelar el material de clave.

**Gap de documentación:** `SKILL.md` de `wireless-network-analyst` (que guía los health checks/troubleshooting en runtime) no menciona estas 3 tools ni las integra en sus flujos. Pendiente decidir si se actualiza la skill — encajarían bien en el bloque de troubleshooting de cliente, sobre todo `diagnosticar_autenticacion` por el veredicto directo.

**Dependencia opcional:** `escanear_a_pcap` necesita el binario `scandump` en `/usr/local/bin/scandump` (instalado 12/09/2026 con `CAP_NET_ADMIN`, no con sudo). Si faltara, `escanear_ssid` cae solo a `iw scan` y solo `escanear_a_pcap` deja de estar operativa. Instrucciones de build en README §Despliegue.

---

## 4. Documentación del proyecto

- **Guía de uso "formato 101"** de las 27 tools: [`docs/guia_101_mcp_tshark.md`](docs/guia_101_mcp_tshark.md) — pensada para quien no conoce el proyecto; incluye sus propias secciones "Problemas conocidos" por capítulo.
- **Problemas encontrados y sus resoluciones/workarounds** (bugs, hallazgos de infraestructura, gaps para un despliegue desde cero): skill de proyecto `wireless-troubleshooting`. No se repiten en este fichero — consultar ahí antes de depurar un fallo ya visto.

## 5. Pendiente

- Decidir si se actualiza `SKILL.md` de `wireless-network-analyst` para: (a) incluir las 3 tools de diagnóstico combinado, (b) incluir `perfilar_cliente_pcap` y `escanear_a_pcap`, (c) reflejar la preferencia `iw` sobre `airmon` (ver skill `wireless-troubleshooting`).
- Validar el IE ext 59 (HE 6 GHz) cuando haya hardware de 6 GHz: hoy sólo está cubierto por vector sintético, porque ni `wlan0` ni `wlan1` operan en esa banda.
- `analizar_ies_pcap` no decodifica el Ext Tag **108 (EHT Operation)**, que sí está presente en los beacons Wi-Fi 7 del entorno. Gap conocido y acotado: no impide detectar Wi-Fi 7 (eso lo da el 106).
- Resto de pendientes de producto (Fases 2-4: roaming, RF/interferencia, persistencia/histórico) — ver `ROADMAP.md`, no se repiten aquí.
