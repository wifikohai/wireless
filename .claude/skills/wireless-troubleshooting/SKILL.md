---
name: wireless-troubleshooting
description: Catálogo de problemas ya investigados en el servidor MCP `tshark-remoto` (proyecto Wireless) y sus resoluciones o workarounds confirmados, más el inventario real de lo que hace falta para desplegar el servidor desde cero. Actívala antes de depurar un fallo de `activar_modo_monitor`/`desactivar_modo_monitor`, una tool que devuelve `None`/vacío inesperadamente, `leer_pcap(modo="wlan")`, un `descifrar=True` que no surte efecto, un fichero de claves WPA que no carga, o antes de preparar/documentar un despliegue nuevo del servidor.
---

# Problemas conocidos y resoluciones — proyecto Wireless

Este fichero es el histórico operativo del proyecto: cada problema real ya investigado, su causa (confirmada o solo como hipótesis razonada) y la solución o workaround que ya ha funcionado. `CLAUDE.md` solo referencia este fichero — el detalle vive aquí para no inflar el contexto que se carga en cada sesión.

---

## 1. `activar_modo_monitor(metodo="airmon")` devuelve error de validación (`None` en vez de texto)

**Síntoma:** al llamar `activar_modo_monitor` (o `desactivar_modo_monitor`) con `metodo="airmon"` sobre `wlan1` o `wlan0`, la tool falla con un error de validación Pydantic porque devolvió `None` en vez de un string — el mismo síntoma que tenían 3 bugs de esta tool ya corregidos y verificados en el código (`ROADMAP.md`, Validación Fase 1, 01/08/2026: faltaba `return salida`, `airmon-ng stop` en vez de `start`, `ip link up` en vez de `down`).

**Descartado:** no son los 3 bugs originales — revisados línea por línea en el código actual, los 3 fixes siguen desplegados. Tampoco es un problema de `_run()` (siempre devuelve string, nunca `None`).

**Causa (hipótesis razonada, no confirmada del todo con logs del instante exacto del fallo):** la rama `airmon` termina con `sudo systemctl restart NetworkManager` (+ `sleep(8)`), como limpieza del VIF managed residual. `wlan0`/`wlan1` están marcadas `unmanaged` en NetworkManager, así que a ellas ese reinicio no debería afectarles — pero la interfaz cableada real del host (ver actualización de la hipótesis más abajo) **sí** está gestionada por NetworkManager, y es probablemente la que lleva la conexión `streamable-http` del propio servidor MCP hacia el cliente. Si el reinicio corta esa conexión un instante a mitad de la llamada, la tool puede acabar devolviendo un valor vacío donde se esperaba texto.

**Solución confirmada:** usar `metodo="iw"` en su lugar. Hace el mismo ciclo (`ip link down` → `iw set type monitor` → `ip link up`) sin tocar NetworkManager en ningún momento. Se ha usado con éxito repetido en la misma sesión donde `airmon` falló dos veces seguidas.

**Recomendación práctica hasta investigarlo a fondo:** preferir siempre `metodo="iw"` sobre `airmon`. Si se confirma la hipótesis de NetworkManager, valorar quitar el paso `systemctl restart NetworkManager` de la rama `airmon` (parece un intento de limpiar el VIF managed residual, pero `iw` ya resuelve eso sin tocarlo) o marcar también la interfaz cableada como excluida de ese restart.

**Vía de escape para el caso de solo escanear:** desde que existe `escanear_a_pcap`, escanear redes ya no necesita modo monitor en absoluto — usa `scandump` sobre `wlan0` en managed. Ese flujo queda fuera del alcance de este problema.

**Pendiente real:** confirmar (o descartar) la hipótesis con logs del host en el instante exacto de un fallo `airmon`. No se ha hecho todavía.

### Actualización de la hipótesis (18/09/2026) — la interfaz gestionada real es `eth1`, no `eth0`

Cuando se investigó este problema por primera vez (10/08/2026), se observó `eth0` en estado `connecting (getting IP configuration)` durante la propia sesión de investigación, y se asumió que `eth0` era la interfaz gestionada relevante. Al revisar el host de nuevo el 18/09/2026 (`nmcli device status`), `eth0` aparece **`disconnected`** — consistente con ser el puerto SPAN pasivo del laboratorio Wazuh-ThreatHunting del mismo host (sin IP propia, no es una interfaz de red normal) — y la interfaz cableada realmente **`connected`**, con IP y perfil de conexión activo ("Wired connection 2"), es **`eth1`**.

Esto no invalida el workaround (`metodo="iw"` sigue siendo la solución correcta y verificada), pero sí desplaza la hipótesis: si el reinicio de NetworkManager corta la conexión del MCP a mitad de una llamada `airmon`, la interfaz afectada sería `eth1`, no `eth0`. `eth0` como SPAN port probablemente ni siquiera participa en esto. Sigue sin confirmarse con logs del instante exacto — pendiente igual que antes, solo que apuntando a la interfaz correcta.

---

## 2. `leer_pcap(modo="wlan")` da un error de tshark en vez de estadísticas

**Síntoma:** pedir `leer_pcap` con `modo="wlan"` devuelve un error de tshark en vez de las estadísticas 802.11 esperadas.

**Causa:** el comando interno usa `-z wlan,stat`, que no es un nombre de estadística válido en la versión de tshark instalada en el host (4.0.17) — el nombre correcto sería `conv,wlan` o `endpoints,wlan`. Pendiente de corregir en el código (`tshark_server.py`, función `leer_pcap`).

**Workaround:** usar `modo="protocolos"` o `modo="conversaciones"` en su lugar — cubren el mismo tipo de necesidad (qué hay en la captura y cómo se agrupa).

Detalle completo para el usuario final en [`docs/guia_101_mcp_tshark.md`](../../../docs/guia_101_mcp_tshark.md), Capítulo 5.

---

## 3. `leer_pcap(descifrar=True)` no cambia nada, sigue viéndose "QoS Data" cifrado

**Causa más probable:** el PCAP no contiene el 4-Way Handshake completo del cliente (mensajes M1-M4). Sin ese handshake no hay forma de derivar la PTK (clave de sesión), y el tráfico unicast sigue viéndose cifrado — el multicast necesita además la GTK, que va en M3.

**Solución:** recapturar cubriendo el momento exacto en que el cliente se reconecta a la red (para que el PCAP incluya el handshake), o usar `diagnosticar_conectividad_cliente` directamente, que ya comprueba explícitamente si el descifrado surtió efecto antes de interpretar DHCP/ARP/DNS, en vez de devolver un resultado vacío engañoso.

Detalle completo en [`docs/guia_101_mcp_tshark.md`](../../../docs/guia_101_mcp_tshark.md), Capítulo 5.

---

## 4. Fichero de claves WPA (`80211_keys`, formato UAT) — gotchas de formato

- **Una sola línea mal formada desactiva el descifrado entero, sin avisar por su cuenta.** tshark rechaza la tabla completa de claves si una sola línea no cumple el formato exacto (comillas, comas) — no solo esa línea. `estado_descifrado_wpa()` sí avisa explícitamente de qué números de línea son inválidos.
- **El SSID se separa por el último `:` de la línea, no el primero.** Si la passphrase contuviera un `:` (poco común), el SSID debe ir siempre al final para que el separado sea correcto.
- **WPA3-SAE no es descifrable con este mecanismo.** Si la red usa SAE puro (sin modo de transición), la passphrase no sirve para derivar la clave de sesión como en WPA2-PSK — `diagnosticar_conectividad_cliente` lo señala como causa posible cuando el descifrado no surte efecto pese a haber handshake.

Detalle completo en [`docs/guia_101_mcp_tshark.md`](../../../docs/guia_101_mcp_tshark.md), Capítulo 7.

---

## 5. Gaps para un despliegue desde cero (encontrados 18/09/2026 — inventario real del host, sin resolver)

Comprobado por SSH contra el host real: el repo documenta **cómo usar** el servidor ya desplegado (README, guía 101), pero no **cómo montarlo desde cero** en otro Raspberry Pi. Ninguna de estas piezas está versionada hoy en el repo; aquí queda el inventario real por si se decide escribir una guía de despliegue:

- **Hardware de modo monitor:** el WiFi integrado de la Raspberry Pi (`wlan0`, phy0) **no soporta modo monitor** (`iw phy` no lista `monitor` entre sus modos). El modo monitor lo da un adaptador **USB externo**: en este host, un `MediaTek MT7612U` (802.11ac, `lsusb` → `0e8d:7612`). Quien replique esto necesita comprar ese tipo de adaptador, no basta con el WiFi de a bordo.
- **Unidad systemd real** (no está en el repo):
  ```ini
  [Unit]
  Description=MCP Tshark Server
  After=network.target

  [Service]
  Type=simple
  User=usuario
  ExecStart=/home/usuario/mcp_tshark/mcp_env/bin/python -u /home/usuario/mcp_tshark/tshark_server.py
  Restart=on-failure

  [Install]
  WantedBy=multi-user.target
  ```
- **Sudoers real** (`/etc/sudoers.d/`, no está en el repo): línea específica heredada `usuario ALL=(root) NOPASSWD: /usr/sbin/iw, /usr/sbin/airmon-ng, /usr/bin/tshark, /usr/bin/ip, /usr/bin/systemctl restart NetworkManager`, más una entrada separada `usuario ALL=(ALL) NOPASSWD: ALL` sin restricción (ver nota de riesgo abajo).
- **Config de NetworkManager** que marca `wlan0`/`wlan1` como `unmanaged` (`/etc/NetworkManager/conf.d/*.conf`, no está en el repo): `[keyfile]` con `unmanaged-devices=interface-name:wlan0;interface-name:wlan1`. Esta es la pieza que hace posible el modo monitor sin que NetworkManager interfiera.
- **Dependencias Python:** no hay `requirements.txt` en el repo. El venv real (`mcp_env`) tiene, entre otros: `mcp==1.28.1`, `scapy==2.7.0`, `pydantic==2.13.4`, `uvicorn==0.49.0`, `starlette==1.3.1`, `cryptography==49.0.0`.
- **Registro del servidor en el cliente MCP** (Claude Desktop/Code apuntando a `http://<ip-del-host>:8000` con transporte `streamable-http`): no hay ningún ejemplo de configuración en el repo.
- **`wireshark_profile/` y permisos:** hay que crear ese directorio a mano antes de poder usar el Capítulo 7 de la guía 101 (dar de alta claves WPA).
- **El propio host tiene un `readme.md` desactualizado** en `/home/usuario/mcp_tshark/readme.md` (distinto del `README.md` de este repo) que describe menos tools que las 27 actuales y define la finalidad del proyecto como "auditoria/pentesting de redes inalambricas" — **contradice el alcance explícito del proyecto** (no es auditoría de seguridad, ver CLAUDE.md §1). Puede confundir a quien lo encuentre directamente en el host en vez de en este repo. Pendiente de corregir o borrar.

**Nota de riesgo, no de bug:** el sudoers del host tiene además una entrada `NOPASSWD: ALL` sin restricción (no solo la lista específica de comandos WiFi) heredada de una configuración previa del sistema. No es algo que haya causado un problema observado, pero para un despliegue nuevo conviene replicar solo la lista de comandos específicos (`iw`, `airmon-ng`, `tshark`, `ip`, `systemctl restart NetworkManager`), no el `ALL` sin restricción.
