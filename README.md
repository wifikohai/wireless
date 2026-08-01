# Wireless

Servidor MCP (`tshark_server.py`) que expone herramientas de captura y análisis 802.11 (tshark/iw/scapy) sobre un adaptador WiFi en modo monitor, para que Claude haga troubleshooting real de cliente/RF sin que el analista tenga que ejecutar tshark a mano.

## Estado

Host: Raspberry Pi (`usuario@10.10.1.142`), interfaz `wlan1` (única con soporte de modo monitor; `wlan0` es managed-only). Servicio systemd `mcp-tshark.service`, FastMCP sobre `streamable-http` en el puerto 8000.

Alcance actual: **troubleshooting de cliente/RF** (no auditoría de seguridad ni pipeline SOC). Ver [ROADMAP.md](ROADMAP.md) para el detalle completo de objetivos, gaps identificados y fases.

- ✅ **Fase 1 — Fallos de autenticación (protocolo):** clasificación EAPOL M1-M4/G1-G2, traducción de reason/status code, decoder de IE RSN (cipher/AKM/PMF). Implementada y validada contra el host real (ver "Validación Fase 1" en el roadmap) — incluyó corregir 4 bugs preexistentes que dejaban el modo monitor completamente inoperativo.
- ⬜ Fase 2 — Fallos de roaming
- ⬜ Fase 3 — "WiFi lento" / interferencia RF
- ⬜ Fase 4 — Persistencia / histórico

## Estructura

- `tshark_server.py` — servidor MCP (23+ tools: descubrimiento de interfaces, modo monitor, captura filtrada en vivo, captura a PCAP, lectura/análisis de PCAP, decodificación de IEs 802.11).
- `ROADMAP.md` — objetivos, gaps identificados en el código, fases, y registro de validación contra el servidor real.

## Despliegue

El código se edita localmente y se despliega a mano al host:

```bash
scp tshark_server.py usuario@10.10.1.142:/home/usuario/mcp_tshark/tshark_server.py.new
ssh usuario@10.10.1.142 "python3 -c \"import ast; ast.parse(open('mcp_tshark/tshark_server.py.new').read())\" && mv mcp_tshark/tshark_server.py.new mcp_tshark/tshark_server.py"
ssh usuario@10.10.1.142 "sudo systemctl restart mcp-tshark.service"
```

Siempre con backup previo del fichero en producción (`tshark_server.py.bak_<timestamp>`) y verificación de sintaxis antes del swap.
