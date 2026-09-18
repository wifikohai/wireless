# Wireless — troubleshooting WiFi con Claude

¿Alguna vez has tenido que decirle a alguien "espera, deja que capture con tshark a ver qué está pasando" y luego perder media hora leyendo hexadecimal? Este proyecto existe para quitarte ese paso de en medio.

`tshark-remoto` es un servidor MCP que le da a Claude acceso directo a un adaptador WiFi en modo monitor sobre una Raspberry Pi. En vez de que tú captures tráfico 802.11 a mano y luego pegues la salida de tshark en el chat, le pides a Claude en lenguaje normal — "¿por qué este cliente no consigue asociarse?", "captúrame los beacons de este SSID", "dime si esta red soporta 802.11r" — y Claude ejecuta la captura, la analiza y te devuelve un diagnóstico.

## ¿Para qué sirve, y para qué no?

Está pensado para troubleshooting real de cliente y de RF: problemas de autenticación, roaming, interferencia, o el clásico "el cliente se asocia pero no navega". **No** es una herramienta de auditoría de seguridad ni un pipeline de SOC — esa fue una decisión deliberada, así que no vas a encontrar aquí integración con APIs de seguridad ni nada orientado a detección de intrusos.

## Qué puede hacer hoy

- **Ver qué hay alrededor**: listar interfaces, consultar capacidades del adaptador, escanear redes y SSIDs concretos.
- **Capturar en vivo, ya filtrado**: beacons, probe requests, autenticación, asociación, EAPOL (4-way handshake), tráfico de management/control/datos, estadísticas de la WLAN — sin que tengas que escribir un filtro de tshark.
- **Trabajar con capturas guardadas (PCAP)**: leerlas, descifrar WPA si hace falta, y sobre todo *interpretarlas*:
  - perfilar un punto de acceso a partir de sus beacons (hasta qué generación WiFi soporta, hasta Wi-Fi 7; si tiene roaming 802.11k/r/v; qué seguridad anuncia),
  - perfilar un cliente a partir de su Association Request (capacidades, bandas, si su MAC está aleatorizada, fabricante por OUI),
  - diagnosticar automáticamente un fallo de autenticación (te dice si fue un timeout del 4-way handshake, un fallo 802.1X, etc., no solo te enseña los paquetes),
  - diagnosticar por qué un cliente asociado no tiene conectividad (revisa DHCP/ARP/DNS descifrando su tráfico).

En total son 27 herramientas — el detalle completo de cada una, con ejemplos de cómo pedírselas a Claude, está en la [guía 101](docs/guia_101_mcp_tshark.md), pensada para que la pueda seguir alguien que no ha tocado este proyecto en su vida.

## Cómo está montado

El servidor corre en una Raspberry Pi con un adaptador USB dedicado (`wlan1`, chipset MediaTek MT7612U) que es el único capaz de entrar en modo monitor — el WiFi integrado de la Pi (`wlan0`) solo puede escanear y asociarse como un cliente normal. El servicio (`mcp-tshark.service`, FastMCP sobre `streamable-http` en el puerto 8000) se despliega y se administra a mano, sin CI/CD: se edita el código en local, se copia por `scp`, se valida la sintaxis y se reinicia el servicio.

## Requisitos

Para usar el servidor tal cual está desplegado, en tu propia máquina solo necesitas:

- Un cliente MCP (Claude Desktop o Claude Code).
- [Node.js](https://nodejs.org/) instalado, porque la conexión pasa por [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) (el servidor habla `streamable-http`, no `stdio`, así que hace falta un puente).
- Acceso de red a la Raspberry Pi (por defecto, `10.10.1.142:8000`).

Si en cambio quieres tocar o redesplegar el propio servidor, necesitas acceso SSH al host y Python 3 en la Raspberry Pi (entorno virtual ya preparado en `/home/usuario/mcp_tshark/mcp_env`).

## Cómo conectarlo a tu Claude

**Claude Desktop** — añade esto en `claude_desktop_config.json` (`%APPDATA%\Claude\claude_desktop_config.json` en Windows; `~/Library/Application Support/Claude/claude_desktop_config.json` en macOS; `~/.config/Claude/claude_desktop_config.json` en Linux):

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

- `--allow-http` hace falta porque el servidor no tiene TLS (pensado solo para la LAN doméstica), así que hay que permitir HTTP explícitamente.
- `--transport http-only` evita que `mcp-remote` pierda tiempo probando SSE (que este servidor no ofrece) antes de caer a streamable-http.
- Reinicia Claude Desktop después de guardar el fichero.

**Claude Code (CLI)** — el mismo resultado sin tocar JSON a mano:

```bash
claude mcp add tshark-remoto -- npx -y mcp-remote http://10.10.1.142:8000/mcp --allow-http --transport http-only
```

Comprueba con `claude mcp list` que aparece como `connected`.

## Estructura del repo

- [`tshark_server.py`](tshark_server.py) — el servidor MCP en sí, con las 27 herramientas.
- [`ROADMAP.md`](ROADMAP.md) — objetivos, fases del proyecto y el registro detallado de validación contra el servidor real.
- [`docs/guia_101_mcp_tshark.md`](docs/guia_101_mcp_tshark.md) — guía paso a paso de las 27 herramientas para quien llega sin contexto previo.
- `.claude/skills/wireless-troubleshooting/` — catálogo de problemas ya investigados en este servidor (bugs de infraestructura, workarounds confirmados) para no repetir la depuración dos veces.
- `.claude/skills/wireless-network-analyst/` — playbook de health checks diarios/semanales, troubleshooting de cliente, auditoría WPA2/WPA3, detección de ataques y análisis forense de PCAP usando las 27 tools.

## En qué punto va esto

- ✅ **Fase 1 — Fallos de autenticación**: clasificación EAPOL (M1-M4/G1-G2), traducción de reason/status codes, decodificación de IEs RSN (cifrado, AKM, PMF). Validada contra el host real.
- ✅ **Descifrado WPA y conectividad post-asociación**: el caso "se asocia pero no navega", resuelto fuera de fase.
- ✅ **IEs modernos y escaneo estructurado**: soporte hasta Wi-Fi 7 (EHT/MLO/6E) y roaming 802.11k/r/v, más las herramientas de perfilado de cliente y escaneo a PCAP. Este bloque se apoyó en el proyecto [WLAN Pi](https://github.com/wlan-pi) como referencia de dominio.
- ⬜ Fase 2 — Fallos de roaming (falta la línea de tiempo del roam y detectar "sticky clients")
- ⬜ Fase 3 — "WiFi va lento" / interferencia de RF
- ⬜ Fase 4 — Persistencia e histórico

El detalle completo, incluidos los bugs encontrados y corregidos por el camino, está en el [ROADMAP.md](ROADMAP.md).

## Descifrado WPA

Viene desactivado por defecto. Si lo necesitas, la clave se crea a mano directamente en el host (nunca como parámetro de una herramienta, porque quedaría registrada en la conversación):

```bash
ssh usuario@10.10.1.142 "umask 077 && printf '%s\n' '\"wpa-pwd\",\"MI_PASSPHRASE:MI_SSID\"' > ~/mcp_tshark/wireshark_profile/80211_keys"
```

`estado_descifrado_wpa()` te confirma que todo está en orden sin revelar nunca el contenido de la clave.

## Desplegar un cambio

No hay pipeline automático: el flujo es editar en local, copiar, validar y reiniciar.

```bash
scp tshark_server.py usuario@10.10.1.142:/home/usuario/mcp_tshark/tshark_server.py.new
ssh usuario@10.10.1.142 "python3 -c \"import ast; ast.parse(open('mcp_tshark/tshark_server.py.new').read())\" && mv mcp_tshark/tshark_server.py.new mcp_tshark/tshark_server.py"
ssh usuario@10.10.1.142 "sudo systemctl restart mcp-tshark.service"
```

Siempre con backup previo del fichero en producción (`tshark_server.py.bak_<timestamp>`) y comprobando la sintaxis antes de reemplazarlo.

### Dependencia opcional: `scandump`

La herramienta `escanear_a_pcap` usa el binario [`scandump`](https://github.com/WLAN-Pi/scandump) para escanear todas las bandas de una pasada sin tocar el modo monitor. No es obligatorio: si no está instalado, `escanear_ssid` simplemente cae al `iw scan` de siempre y el resto del servidor sigue funcionando igual.

```bash
sudo apt-get install -y build-essential libnl-genl-3-dev libpcap-dev
git clone https://github.com/WLAN-Pi/scandump && cd scandump && make
sudo install -m 755 scandump /usr/local/bin/scandump
sudo setcap cap_net_admin+ep /usr/local/bin/scandump
```

El `setcap` es intencional: así `scandump` escanea con `CAP_NET_ADMIN` en vez de necesitar sudo completo.

## Referencias

- [WLAN Pi](https://github.com/wlan-pi) — proyecto open-source de hardware/software para troubleshooting WiFi, usado aquí como referencia de dominio para el enfoque de diagnóstico de cliente/RF.
