# Wireless

Servidor MCP (`tshark_server.py`) que expone herramientas de captura y análisis 802.11 (tshark/iw/scapy) sobre un adaptador WiFi en modo monitor, para que Claude haga troubleshooting real de cliente/RF sin que el analista tenga que ejecutar tshark a mano.

## Estado

Host: Raspberry Pi (`usuario@10.10.1.142`), interfaz `wlan1` (única con soporte de modo monitor; `wlan0` es managed-only). Servicio systemd `mcp-tshark.service`, FastMCP sobre `streamable-http` en el puerto 8000.

Alcance actual: **troubleshooting de cliente/RF** (no auditoría de seguridad ni pipeline SOC). Ver [ROADMAP.md](ROADMAP.md) para el detalle completo de objetivos, gaps identificados y fases.

- ✅ **Fase 1 — Fallos de autenticación (protocolo):** clasificación EAPOL M1-M4/G1-G2, traducción de reason/status code, decoder de IE RSN (cipher/AKM/PMF). Implementada y validada contra el host real (ver "Validación Fase 1" en el roadmap) — incluyó corregir 4 bugs preexistentes que dejaban el modo monitor completamente inoperativo.
- ✅ **Descifrado WPA / conectividad post-asociación** (fuera de fase, 06/08/2026): caso "asocia pero no navega". Ver la sección correspondiente en el roadmap.
- ✅ **Modernización de IEs y escaneo estructurado** (fuera de fase, 12/09/2026): decodificación hasta Wi-Fi 7 (EHT/MLO/6E), soporte de roaming 802.11k/r/v en AP y cliente, tools nuevas `perfilar_cliente_pcap` y `escanear_a_pcap`. Derivado de adoptar [WLAN Pi](https://github.com/wlan-pi) como referencia; corrigió 6 bugs preexistentes. Ver la sección correspondiente en el roadmap.
- ⬜ Fase 2 — Fallos de roaming (el bloque de IEs k/r/v ya está hecho; falta la línea de tiempo del roam y la detección de sticky client)
- ⬜ Fase 3 — "WiFi lento" / interferencia RF
- ⬜ Fase 4 — Persistencia / histórico

## Estructura

- `tshark_server.py` — servidor MCP (27 tools: descubrimiento de interfaces, modo monitor, captura filtrada en vivo, captura a PCAP, lectura/análisis de PCAP, decodificación de IEs 802.11 hasta Wi-Fi 7, perfilado de clientes, escaneo estructurado, descifrado WPA).
- `ROADMAP.md` — objetivos, gaps identificados en el código, fases, y registro de validación contra el servidor real.
- [`docs/guia_101_mcp_tshark.md`](docs/guia_101_mcp_tshark.md) — guía "formato 101" de las 27 tools del servidor MCP: qué hace cada una, cómo pedírselo a Claude y flujos completos de ejemplo, pensada para quien no conoce el proyecto.

## Integración MCP en el cliente

El servidor expone MCP sobre `streamable-http`, no `stdio`. Un cliente que solo sabe lanzar procesos locales (como Claude Desktop) necesita un puente: se usa [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) (requiere Node.js/`npx` instalado en la máquina del cliente, no en el host) para traducir stdio ↔ HTTP.

**Claude Desktop** — añadir en `claude_desktop_config.json` (`%APPDATA%\Claude\claude_desktop_config.json` en Windows; `~/Library/Application Support/Claude/claude_desktop_config.json` en macOS; `~/.config/Claude/claude_desktop_config.json` en Linux):

```json
"tshark-remoto": {
  "command": "npx",
  "args": [
    "-y",
    "mcp-remote",
    "http://10.10.1.142:8000/mcp",
    "--allow-http",
    "--transport",
    "http-only"
  ]
}
```

- `--allow-http`: el servidor no tiene TLS (solo pensado para la LAN doméstica), así que hay que permitir HTTP explícitamente o `mcp-remote` lo rechaza.
- `--transport http-only`: evita que `mcp-remote` pruebe primero SSE (este servidor no lo expone) antes de caer a streamable-http, así falla rápido si el host no responde en vez de colgarse en el fallback.
- Reiniciar Claude Desktop tras editar el fichero para que recargue la config.

**Claude Code (CLI)** — equivalente sin editar JSON a mano:

```bash
claude mcp add tshark-remoto -- npx -y mcp-remote http://10.10.1.142:8000/mcp --allow-http --transport http-only
```

Verificar con `claude mcp list` que queda como `connected`.

## Descifrado WPA

Desactivado por defecto. Para activarlo, crear a mano en el host el fichero de claves (formato UAT de Wireshark, permisos 600):

```bash
ssh usuario@10.10.1.142 "umask 077 && printf '%s\n' '\"wpa-pwd\",\"MI_PASSPHRASE:MI_SSID\"' > ~/mcp_tshark/wireshark_profile/80211_keys"
```

Las claves no se pasan nunca como parámetro de una tool (quedarían en la conversación) ni en la línea de comandos de tshark (visible vía `ps`): se le pasan a tshark con `WIRESHARK_CONFIG_DIR` apuntando a `~/mcp_tshark/wireshark_profile/`. `estado_descifrado_wpa()` verifica el estado sin revelar el material de clave.

## Despliegue

El código se edita localmente y se despliega a mano al host:

```bash
scp tshark_server.py usuario@10.10.1.142:/home/usuario/mcp_tshark/tshark_server.py.new
ssh usuario@10.10.1.142 "python3 -c \"import ast; ast.parse(open('mcp_tshark/tshark_server.py.new').read())\" && mv mcp_tshark/tshark_server.py.new mcp_tshark/tshark_server.py"
ssh usuario@10.10.1.142 "sudo systemctl restart mcp-tshark.service"
```

Siempre con backup previo del fichero en producción (`tshark_server.py.bak_<timestamp>`) y verificación de sintaxis antes del swap.

### Dependencia opcional: `scandump`

`escanear_a_pcap` requiere el binario [`scandump`](https://github.com/WLAN-Pi/scandump) (C, BSD-3-Clause), y `escanear_ssid` lo aprovecha si está presente. **No es obligatorio**: sin él, `escanear_ssid` cae automáticamente al parseo de `iw scan` y el resto del servidor no se entera.

Se instala una sola vez en el host:

```bash
sudo apt-get install -y build-essential libnl-genl-3-dev libpcap-dev
git clone https://github.com/WLAN-Pi/scandump && cd scandump && make
sudo install -m 755 scandump /usr/local/bin/scandump
sudo setcap cap_net_admin+ep /usr/local/bin/scandump
```

El `setcap` es deliberado: escanea con `CAP_NET_ADMIN` en vez de con sudo completo. Verificar con `/sbin/getcap /usr/local/bin/scandump`.

## Referencias externas

- [WLAN Pi](https://github.com/wlan-pi) — proyecto open-source de hardware/software para troubleshooting WiFi (captura, análisis 802.11, herramientas de RF). Referencia de dominio para el enfoque de diagnóstico de cliente/RF de este proyecto.
