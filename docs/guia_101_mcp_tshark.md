# Guía 101 — Servidor MCP `tshark-remoto` (proyecto Wireless)

> Guía pensada para alguien que **no conoce nada de este proyecto**: ni qué es MCP, ni qué es el modo monitor, ni cómo se lee una captura WiFi. Si ya conoces estos conceptos, salta directamente al [Capítulo 1](#capítulo-1--interfaces-y-capacidades-3-tools).
>
> Esta guía documenta **las 27 herramientas (tools)** que expone el servidor `tshark-remoto` y cómo usarlas para sacarles el máximo partido. Para el mapa de ficheros del repo ver [`README.md`](../README.md); para objetivos/fases del proyecto ver [`ROADMAP.md`](../ROADMAP.md); para el estado operativo y hallazgos abiertos ver [`CLAUDE.md`](../CLAUDE.md).

---

## Índice

- [Capítulo 0 — Qué es esto y para qué sirve](#capítulo-0--qué-es-esto-y-para-qué-sirve)
- [Capítulo 0.5 — Conceptos básicos (léelo si es tu primera vez)](#capítulo-05--conceptos-básicos-léelo-si-es-tu-primera-vez)
- [Capítulo 1 — Interfaces y capacidades (3 tools)](#capítulo-1--interfaces-y-capacidades-3-tools)
- [Capítulo 2 — Modo monitor y canal (3 tools)](#capítulo-2--modo-monitor-y-canal-3-tools)
- [Capítulo 3 — Escaneo y survey (4 tools)](#capítulo-3--escaneo-y-survey-4-tools)
- [Capítulo 4 — Captura en tiempo real (9 tools)](#capítulo-4--captura-en-tiempo-real-9-tools)
- [Capítulo 5 — Captura y análisis de PCAP (5 tools)](#capítulo-5--captura-y-análisis-de-pcap-5-tools)
- [Capítulo 6 — Diagnóstico combinado: el atajo recomendado (3 tools)](#capítulo-6--diagnóstico-combinado-el-atajo-recomendado-3-tools)
- [Capítulo 7 — Descifrado WPA: configurar las claves](#capítulo-7--descifrado-wpa-configurar-las-claves)
- [Capítulo 8 — Flujos completos de ejemplo (recetas end-to-end)](#capítulo-8--flujos-completos-de-ejemplo-recetas-end-to-end)
- [Apéndice — Tabla resumen de las 27 tools](#apéndice--tabla-resumen-de-las-27-tools)

---

## Capítulo 0 — Qué es esto y para qué sirve

`tshark-remoto` es un servidor que corre en una Raspberry Pi y que le da a Claude 27 "herramientas" (en la jerga MCP, **tools**) para capturar y analizar tráfico WiFi (802.11) real, usando por debajo programas estándar de Linux (`tshark`, `iw`, `scapy`). Tú no ejecutas esos comandos a mano: **le pides a Claude en el chat** lo que quieres investigar, y Claude decide qué tools invocar.

**Para qué sirve (alcance):** troubleshooting de **cliente/RF** — es decir, diagnosticar problemas como "este dispositivo no consigue conectarse al WiFi", "se conecta pero no navega", o (en fases futuras del proyecto, ver `ROADMAP.md`) "el WiFi va lento" o "el roaming entre puntos de acceso falla".

**Para qué NO sirve (fuera de alcance, decisión explícita del proyecto):** no es una herramienta de auditoría de seguridad ni un pipeline de un SOC (Security Operations Center). No hace nada ofensivo (no rompe redes, no fuerza desconexiones) ni se integra con sistemas de gestión de red tipo Meraki.

**Las piezas que hay que tener claras desde ya:**
- Hay un **host remoto** (una Raspberry Pi) que es quien realmente tiene el adaptador WiFi y ejecuta las capturas.
- Ese host tiene un **servicio** corriendo (`mcp-tshark.service`) que escucha peticiones y las traduce en comandos reales (`tshark`, `iw`...).
- Tú (o quien use esta guía) interactúas con todo esto **hablando con Claude**, no conectándote tú mismo por SSH salvo para un puñado de tareas administrativas muy concretas que se explican en el [Capítulo 7](#capítulo-7--descifrado-wpa-configurar-las-claves) y no forman parte del uso normal día a día.

---

## Capítulo 0.5 — Conceptos básicos (léelo si es tu primera vez)

Si ya sabes qué es un servidor MCP, qué es el modo monitor en WiFi, y qué es un PCAP, puedes saltarte este capítulo entero.

### ¿Qué es "MCP" y qué es una "tool"?

MCP (Model Context Protocol) es un protocolo que permite que un asistente como Claude llame a funciones ("tools") expuestas por un servidor externo, como si fueran comandos que el asistente puede ejecutar por ti. Cada una de las 27 funciones de este proyecto (p. ej. `listar_interfaces`, `capturar_a_pcap`) es una **tool**: tiene un nombre, unos parámetros de entrada, y devuelve texto con el resultado.

**Cómo se invoca una tool en la práctica:** no hay una sintaxis especial que tengas que aprender. Simplemente le pides a Claude, en lenguaje natural, lo que quieres ("¿qué interfaces WiFi hay disponibles?", "activa el modo monitor en wlan1", "captura 30 segundos de tráfico y guárdalo"), y Claude elige la tool adecuada y rellena sus parámetros. Esta guía te explica **qué hace cada tool por dentro** y **qué pedir** para conseguir cada resultado, para que sepas qué es posible y cómo interpretar lo que Claude te devuelva.

### ¿Dónde se ejecutan realmente las cosas?

Aunque tú hables con Claude desde tu ordenador, **todas las tools de este capítulo en adelante se ejecutan en el host remoto** (la Raspberry Pi, `usuario@10.10.1.142`), no en tu máquina. Eso es justo lo que aporta el servidor MCP: te da acceso a un adaptador WiFi físico que solo existe ahí. Cuando esta guía diga "esto se ejecuta en el host" (fuera del flujo normal de tools) se referirá a comandos manuales por SSH, que son la excepción, no la norma — se explican en el [Capítulo 7](#capítulo-7--descifrado-wpa-configurar-las-claves).

### Modo monitor vs. modo managed

Un adaptador WiFi normal (**modo managed**) solo puede hacer dos cosas: conectarse a una red conocida, o escanear qué redes hay alrededor. No puede "ver" el tráfico crudo de otros dispositivos ni los detalles de bajo nivel del protocolo 802.11 (autenticación, retransmisiones, etc.).

El **modo monitor** convierte el adaptador en un receptor pasivo: deja de poder conectarse a redes, pero puede capturar **cualquier** trama 802.11 que pase por el aire en el canal en el que esté sintonizado — de forma parecida a poner una radio en un canal concreto y escuchar todo lo que se emite ahí, vengas o no de tu propia red. Es imprescindible para casi todo el troubleshooting de este proyecto (ver auth/EAPOL, retries, etc.).

**Limitación importante de este proyecto:** solo una interfaz (`wlan1`) soporta modo monitor, y solo puede escuchar **un canal a la vez** — no existe multi-canal simultáneo con el hardware actual. La otra interfaz (`wlan0`) es managed-only: solo sirve para escanear redes o asociarse de verdad como un cliente normal.

### Canal, banda y ancho de banda

Una red WiFi transmite en una **banda** (2.4 GHz, 5 GHz o 6 GHz) dividida en **canales** numerados (p. ej. canal 6 en 2.4 GHz, canal 36 en 5 GHz). El **ancho de banda** (20/40/80/160 MHz) es cuánto "espacio" de esa banda ocupa la transmisión — más ancho, más velocidad potencial, pero más sensible a interferencia. Para capturar el tráfico de una red concreta, el adaptador en modo monitor tiene que estar **sintonizado en el mismo canal y ancho** que esa red (eso es lo que hace la tool `fijar_canal`, ver [Capítulo 2](#capítulo-2--modo-monitor-y-canal-3-tools)).

### SSID, BSSID, y tipos de trama 802.11

- **SSID**: el nombre de la red que ves al buscar WiFi (p. ej. "MiWifi_5G").
- **BSSID**: la dirección MAC física del punto de acceso que emite esa red — el identificador único de "ese router/AP en concreto", útil cuando hay varios repetidores con el mismo SSID.
- Las tramas 802.11 se dividen en tres tipos: **management** (autenticación, asociación, y **beacons** — la trama que cada AP emite varias veces por segundo, sin que nadie se lo pida, anunciando "aquí estoy, me llamo así, y sé hacer esto" — es cómo se anuncia y organiza la red), **control** (ACK, RTS/CTS — mecanismos internos de bajo nivel para evitar colisiones) y **data** (el tráfico real de datos del usuario).

### El 4-Way Handshake y EAPOL

Cuando un dispositivo se conecta a una red protegida (WPA2/WPA3), antes de poder enviar tráfico real tiene que completar un intercambio de 4 mensajes con el punto de acceso para acordar las claves de cifrado de la sesión — el **4-Way Handshake**, transportado en tramas de tipo **EAPOL**. Los mensajes se numeran M1→M2→M3→M4. Si este intercambio falla o se queda a medias (típicamente por una contraseña incorrecta, o por incompatibilidad de parámetros de seguridad), el dispositivo nunca llega a asociarse de verdad aunque parezca que "casi" lo consigue. Diagnosticar exactamente en qué mensaje se corta este intercambio es una de las capacidades centrales de este proyecto (`capturar_eapol`, `diagnosticar_autenticacion`).

### RSN, AKM y PMF (los parámetros de seguridad de una red)

El **RSN** (Robust Security Network) es un bloque de información que cada red WiFi protegida anuncia en sus beacons, describiendo cómo hay que autenticarse y cifrar. Dentro de él:
- **AKM** (Authentication and Key Management): el método de autenticación — p. ej. `PSK` (contraseña compartida, WPA2-Personal), `SAE` (WPA3-Personal), `802.1X` (WPA2/3-Enterprise, con un servidor **RADIUS**: un servidor centralizado que verifica usuario y contraseña por cada dispositivo, en vez de una única contraseña compartida por todos).
- **Cipher** (cifrado): el algoritmo usado para cifrar el tráfico, p. ej. `CCMP-128 (AES)`.
- **PMF** (Protected Management Frames): si la red exige o admite proteger también las tramas de gestión (no solo los datos) contra manipulación. Puede ser "no soportado", "capaz (opcional)" o "requerido (obligatorio)".

Estos tres valores tienen que ser compatibles entre cliente y AP para que la conexión funcione — una incompatibilidad aquí es una causa típica de fallo silencioso de autenticación.

### PCAP: capturar a fichero vs. capturar "en vivo"

Este proyecto ofrece dos formas de capturar tráfico:
- **En vivo, a texto** (Capítulo 4): la tool captura N paquetes y te devuelve directamente el resultado ya resumido en texto. Rápido, pero solo ves lo que pediste ver en ese momento.
- **A fichero PCAP** (Capítulo 5): la tool graba el tráfico crudo en un fichero `.pcap` en el host durante un tiempo dado. Después puedes releer ese mismo fichero las veces que quieras, con distintos filtros y modos de análisis, sin tener que repetir la captura — muy útil cuando el evento que buscas (una reconexión, un fallo puntual) puede tardar en repetirse.

### Descifrado WPA: por qué está desactivado por defecto

Por defecto, el tráfico de datos de una red protegida se ve cifrado (no se puede leer DHCP/ARP/DNS/HTTP). Este proyecto puede descifrarlo **si tiene la contraseña de la red guardada en el host** (nunca en la conversación con Claude, ver por qué en el [Capítulo 7](#capítulo-7--descifrado-wpa-configurar-las-claves)). Sin ese paso previo (manual, una sola vez por red), el descifrado simplemente no está disponible.

### `sudo`: privilegios de administrador

Muchas de las tools ejecutan por debajo comandos que requieren privilegios de administrador (cambiar el modo de una interfaz de red, fijar un canal...). Eso se hace anteponiendo `sudo` ("superuser do") al comando. En este host concreto está configurado para no pedir contraseña (`NOPASSWD`), así que no es algo que tengas que gestionar tú — se menciona aquí solo para que entiendas por qué algunas tools "tocan" el sistema a un nivel que una aplicación normal no podría.

### SSH: la única vez que tú, y no Claude, te conectas al host

Todo lo de los Capítulos 1-6 lo hace Claude por ti a través de las tools — nunca necesitas conectarte tú mismo al host para eso. La única excepción es el [Capítulo 7](#capítulo-7--descifrado-wpa-configurar-las-claves) (dar de alta una contraseña WPA), porque esa contraseña no debe pasar nunca por la conversación con Claude.

Para esa excepción se usa **SSH** (Secure Shell): un protocolo que abre una terminal remota cifrada contra otro ordenador, como si estuvieras tecleando físicamente delante de él. La sintaxis que verás en esta guía es siempre la misma forma:

```bash
ssh usuario@host "comando a ejecutar en el host remoto"
```

Esto se lanza **desde tu propio ordenador** (necesitas tener el cliente `ssh` instalado — viene de serie en Linux/macOS; en Windows, en PowerShell moderno o en Git Bash) y hace tres cosas: se conecta al `host` como `usuario` (te pedirá su contraseña la primera vez, o usará una clave si ya está configurada), ejecuta el `comando` entre comillas **en el host remoto**, y te devuelve su salida en tu propia terminal. No se abre ninguna sesión interactiva que tengas que cerrar a mano: el comando corre y `ssh` termina solo.

### Dos tipos de filtro, y por qué importa no confundirlos

Vas a ver dos parámetros llamados "filtro" en tools distintas, y no son intercambiables:
- **Filtro de captura (BPF)** — se aplica **mientras se captura**, antes de que el paquete llegue siquiera a guardarse (parámetro `filtro_captura` en `capturar_a_pcap`, Capítulo 5). Usa una sintaxis compacta tipo `"type mgt"` o `"wlan host AA:BB:CC:DD:EE:FF"`. Si el filtro no encaja con nada, esos paquetes **no se guardan en absoluto** — no hay forma de recuperarlos después.
- **Filtro de pantalla (display filter)** — se aplica **después**, sobre una captura ya guardada, para decidir qué paquetes *mostrar* de los que ya están todos ahí (parámetro `filtro` en `leer_pcap`, Capítulo 5). Usa la sintaxis de Wireshark, más expresiva, tipo `"wlan.fc.type_subtype==0x0c"`. Puedes cambiarlo y volver a probar cuantas veces quieras sin perder nada.

En la práctica: si dudas de qué vas a necesitar, captura sin filtro de captura (o uno muy amplio) y afina después con el filtro de pantalla sobre el PCAP ya guardado — es reversible, el otro no.

---

## Capítulo 1 — Interfaces y capacidades (3 tools)

Estas tres tools son el punto de partida de cualquier sesión: sirven para averiguar qué adaptadores WiFi hay disponibles en el host y qué son capaces de hacer, antes de tocar nada.

### `listar_interfaces()`

**Qué hace:** lista todas las interfaces de red que tshark puede usar para capturar, y por separado el detalle de las interfaces WiFi (`iw dev`).

**Cuándo pedirlo:** al empezar cualquier sesión nueva, o si no te acuerdas de si una interfaz se llama `wlan1` o `wlan1mon` en este momento (el nombre cambia según el método usado para activar el modo monitor, ver Capítulo 2).

**Cómo pedirlo:** "¿qué interfaces WiFi hay disponibles en el servidor?"

**Qué esperar (checkpoint):** una lista con al menos `wlan0` (managed-only) y `wlan1` (la única con modo monitor). Si `wlan1` aparece como `wlan1mon` es que ya está en modo monitor de una sesión anterior.

### `info_interfaz(interfaz)`

**Qué hace:** muestra el estado actual de una interfaz concreta — modo (managed/monitor), canal, potencia de transmisión.

**Parámetros:** `interfaz` — el nombre exacto (p. ej. `"wlan1"` o `"wlan1mon"`, según lo que haya devuelto `listar_interfaces`).

**Cuándo pedirlo:** para confirmar en qué canal está sintonizada una interfaz antes de lanzar una captura, o para verificar que un cambio de modo/canal se aplicó de verdad.

**Cómo pedirlo:** "muéstrame el estado de wlan1 ahora mismo".

### `capacidades_phy()`

**Qué hace:** vuelca las capacidades físicas de los adaptadores (`iw phy`): qué bandas soportan (2.4/5/6 GHz), qué anchos de canal, y si soportan HT/VHT/HE (es decir, Wi-Fi 4/5/6).

**Cuándo pedirlo:** solo la primera vez, o si dudas de si el hardware soporta algo concreto (p. ej. si `wlan1` puede capturar en 6 GHz). No cambia entre sesiones — es información del hardware, no del estado actual.

**Cómo pedirlo:** "¿qué capacidades tiene el hardware WiFi del servidor?"

---

## Capítulo 2 — Modo monitor y canal (3 tools)

Antes de poder capturar cualquier tráfico crudo 802.11 (Capítulos 4, 5 y 6), la interfaz `wlan1` tiene que estar en **modo monitor** y sintonizada en el **canal** correcto.

### `activar_modo_monitor(interfaz, metodo="airmon")`

**Qué hace:** convierte una interfaz managed en una interfaz de modo monitor.

**Parámetros:**
- `interfaz`: la interfaz base, p. ej. `"wlan1"`.
- `metodo`: `"airmon"` o `"iw"` — dos formas distintas de hacer lo mismo.

**⚠️ Usa `metodo="iw"`, no el valor por defecto `"airmon"`.** `airmon` ha fallado en sesiones reales sobre este host; `iw` hace el mismo trabajo (bajar interfaz → modo monitor → subir interfaz) y se ha usado con éxito repetido. El porqué completo está en "Problemas conocidos" al final de este capítulo — no hace falta leerlo para seguir adelante, solo para entender la razón si te lo preguntas.

**Cómo pedirlo:** "activa el modo monitor en wlan1 usando el método iw".

**Checkpoint:** la respuesta incluye al final una verificación (`iw dev <interfaz> info`) donde `type monitor` debe aparecer explícitamente. Si no ves esa línea, el cambio no se aplicó — no sigas al siguiente paso (`fijar_canal` fallará con la interfaz aún en managed).

### `fijar_canal(interfaz, canal, ancho="HT20")`

**Qué hace:** sintoniza la interfaz (ya en modo monitor) en un canal y ancho de banda concretos.

**Parámetros:**
- `interfaz`: la interfaz monitor, p. ej. `"wlan1"` (o `"wlan1mon"` si el nombre cambió al activar el modo monitor).
- `canal`: número de canal — 1-13 en 2.4 GHz, 36-165 en 5 GHz, 1-233 en 6 GHz.
- `ancho`: `"HT20"` (20 MHz, valor por defecto y el más compatible), `"HT40+"`/`"HT40-"` (40 MHz), `"80MHz"`, `"160MHz"`.

**Cómo saber qué canal usar:** si no lo sabes de antemano, usa antes `escanear_redes` o `escanear_ssid` (Capítulo 3) con `wlan0` en modo managed para ver en qué canal está emitiendo la red que te interesa.

**Cómo pedirlo:** "fija el canal 6 en wlan1mon, ancho HT20".

**Checkpoint:** la respuesta incluye una verificación con el canal actual — confirma que coincide con el que pediste antes de lanzar una captura larga.

### `desactivar_modo_monitor(interfaz, metodo="airmon")`

**Qué hace:** devuelve la interfaz a modo managed (para poder volver a asociarse a una red normalmente, o simplemente para liberar el adaptador al terminar).

**Parámetros:** igual que `activar_modo_monitor`. **El `metodo` debe coincidir con el que usaste para activarlo** — si lo activaste con `iw`, desactívalo con `iw`; mezclar métodos puede dejar la interfaz en un estado inconsistente.

**Recomendación:** por la misma razón que en `activar_modo_monitor`, usa `metodo="iw"`.

**Cómo pedirlo:** "desactiva el modo monitor en wlan1mon con el método iw".

### Problemas conocidos (Capítulo 2)

- **`activar_modo_monitor(metodo="airmon")` (o `desactivar_modo_monitor` con el mismo método) devuelve un error de validación en vez del resultado esperado**, con el mismo síntoma que unos bugs de esta misma tool que ya se habían corregido y verificado en el código (revisado línea por línea, siguen bien). **Causa (hipótesis razonada, no confirmada del todo con logs del instante exacto del fallo):** la rama `airmon` termina el proceso reiniciando el servicio `NetworkManager` de todo el host, como parte de su limpieza interna de la interfaz. `wlan0` y `wlan1` no dependen de NetworkManager (están marcadas "unmanaged"), así que a ellas ese reinicio no debería afectarles — pero `eth0`, la interfaz cableada del mismo host, **sí** está gestionada por NetworkManager, y es probablemente la interfaz por la que circula la propia conexión de Claude a este servidor MCP. Si el reinicio corta esa conexión durante un instante, la llamada puede acabar devolviendo un valor vacío donde se esperaba texto. **Solución confirmada:** usa `metodo="iw"` en su lugar — hace el mismo ciclo (bajar interfaz → modo monitor → subir interfaz) sin tocar NetworkManager en ningún momento, y se ha usado con éxito repetido en la misma sesión donde `airmon` falló dos veces seguidas.
- **Nota aparte, sin relación con el fallo anterior:** si lo único que quieres es *escanear* redes (no capturar tráfico), desde que existe `escanear_a_pcap` (Capítulo 3) ya no necesitas modo monitor en absoluto para eso — con lo que ese flujo entero queda fuera del alcance de este problema.

---

## Capítulo 3 — Escaneo y survey (4 tools)

Estas tools no requieren modo monitor — trabajan con `wlan0` (managed) o dan información pasiva del canal ya sintonizado.

### `escanear_redes(interfaz)`

**Qué hace:** escaneo activo de redes visibles (`iw scan`), salida en bruto (aunque se resume automáticamente si es muy larga).

**Parámetros:** `interfaz` — normalmente `"wlan0"` (managed).

**Cómo pedirlo:** "escanea las redes WiFi visibles desde wlan0".

### `escanear_ssid(interfaz="wlan0", ssid="")`

**Qué hace:** lo mismo que `escanear_redes`, pero ya parseado en una tabla legible: SSID, BSSID, canal, frecuencia, señal (dBm) y tipo de seguridad. Si le das un `ssid`, filtra por las redes cuyo nombre **contenga** ese texto — útil cuando hay varios APs/repetidores con el mismo nombre y quieres verlos por separado (BSSID distinto = AP físico distinto).

**Cómo pedirlo:** "busca la red 'MiWifi_5G' y dime en qué canal está cada punto de acceso".

**Dos motores por debajo.** La cabecera de la salida te dice cuál se usó:

- `(via scandump)` — el bueno. Lee la seguridad del IE RSN de verdad, así que distingue `WPA3/PMF-req` de `WPA2` o `WPA3/WPA2/PMF-opt` en lugar de una etiqueta genérica.
- `(via iw scan)` — el de reserva, si `scandump` no está instalado. Funciona, pero la seguridad es aproximada.

No tienes que elegir: la tool usa el primero si puede y cae al segundo sola.

**Checkpoint:** el filtro de SSID es por subcadena e **insensible a mayúsculas** (p. ej. `livebox` encuentra `Livebox7-XXXX`). Si aun así no aparece nada, comprueba que `wlan0` no esté en modo monitor en ese momento — en monitor no puede escanear.

### `escanear_a_pcap(interfaz="wlan0", frecuencias="", pasivo=True, nombre="")`

**Qué hace:** escanea y guarda el resultado como fichero `.pcap` en lugar de como texto. Por dentro usa `scandump`, que pregunta al kernel por las redes visibles y escribe las tramas beacon tal cual, sin convertirlas a texto por el camino.

**Por qué importa (lo interesante):** **no necesita modo monitor**. Trabaja sobre `wlan0` en modo normal y barre **todas las bandas de una sola pasada**. Comparado con capturar beacons en monitor, que te ata a un único canal: en una prueba real dio 22 puntos de acceso de 2.4 y 5 GHz, frente a 6 de un solo canal.

**Parámetros:**
- `interfaz` — `"wlan0"` (managed).
- `frecuencias` — lista en MHz separada por comas, ej. `"2437,5180"`. Vacío = todas.
- `pasivo` — `True` (por defecto) se limita a escuchar; `False` emite probe requests.
- `nombre` — nombre del `.pcap`. Si lo omites se genera con fecha y hora.

**Cómo pedirlo:** "escanea todas las redes a fichero y luego analiza las capacidades de los APs".

**Para qué sirve de verdad:** es el primer paso de la receta C. Te da un `.pcap` que puedes pasar directo a `analizar_ies_pcap` para ver generación Wi-Fi, seguridad y soporte de roaming de **todos** los APs del entorno, sin tocar el modo monitor.

**Checkpoint:** si responde que `scandump` no está instalado, te da las instrucciones de instalación. Mientras tanto `escanear_ssid` sigue funcionando.

### `survey_canales(interfaz)`

**Qué hace:** vuelca el "survey" de canal (`iw survey dump`): ruido y ocupación del canal en el que esté sintonizada la interfaz **en este momento** (requiere modo monitor y haber fijado ya un canal con `fijar_canal`).

**Nota de alcance actual:** hoy esta tool devuelve el dato en crudo, sin calcular un porcentaje de utilización ni un ranking — ese cálculo está previsto para la Fase 3 del roadmap (interferencia RF), todavía no implementada. Útil hoy como dato de apoyo, no como veredicto por sí solo.

---

## Capítulo 4 — Captura en tiempo real (9 tools)

Todas requieren que la interfaz ya esté en **modo monitor y en el canal correcto** (Capítulo 2). Capturan un número fijo de paquetes (parámetro `paquetes`, no segundos) y devuelven el resultado ya resumido en una tabla de texto — no se guarda nada a fichero (para eso está el Capítulo 5).

Por eficiencia, si tu objetivo es un diagnóstico completo de fallo de autenticación, **usa directamente `diagnosticar_autenticacion` del Capítulo 6** en vez de encadenar `capturar_autenticacion` + `capturar_eapol` a mano — hace lo mismo en una sola llamada y añade un veredicto.

| Tool | Qué captura | Parámetros | Para qué sirve |
|---|---|---|---|
| `capturar_management(interfaz, paquetes=20)` | Todas las tramas de gestión (beacons, probe, assoc, auth, deauth) | interfaz, nº paquetes | Vista general de "qué está pasando" en el canal |
| `capturar_beacons(interfaz, paquetes=30)` | Solo beacons | interfaz, nº paquetes | Ver qué APs/SSIDs anuncian ese canal, con señal |
| `capturar_probe_requests(interfaz, paquetes=30)` | Probe requests | interfaz, nº paquetes | Qué dispositivos están buscando redes y qué SSID piden |
| `capturar_autenticacion(interfaz, paquetes=20)` | Auth, deauth, disassoc — con `reason_code` **ya traducido a texto** | interfaz, nº paquetes | Ver por qué se desconecta o rechaza un cliente |
| `capturar_asociacion(interfaz, paquetes=20)` | Assoc/reassoc request/response — con `status_code` **ya traducido a texto** | interfaz, nº paquetes | Ver si una asociación fue aceptada y con qué motivo si no |
| `capturar_eapol(interfaz, paquetes=20)` | Frames EAPOL del 4-Way Handshake, **ya clasificados en M1-M4/G1-G2** con detección de retransmisión/handshake incompleto | interfaz, nº paquetes | Diagnóstico fino de fallos de autenticación WPA/WPA2/WPA3 |
| `capturar_datos(interfaz, paquetes=20)` | Tramas de datos (tráfico real) | interfaz, nº paquetes | Confirmar que hay tráfico circulando tras la asociación |
| `capturar_control(interfaz, paquetes=20)` | Tramas de control (ACK, RTS, CTS) | interfaz, nº paquetes | Diagnóstico de bajo nivel, poco usado en troubleshooting normal |
| `estadisticas_wlan(interfaz, segundos=15)` | Estadística por tipo/subtipo de trama durante N **segundos** (no paquetes) | interfaz, segundos | Vista rápida de qué proporción de tráfico es de cada tipo |

**Cómo pedirlo (ejemplos):**
- "captura 20 paquetes de autenticación en wlan1mon y dime si hay algún deauth"
- "captura el 4-way handshake en wlan1mon durante los próximos intentos de conexión de mi portátil"

**Checkpoint común a todas:** si la respuesta viene vacía o dice "(sin salida)"/timeout, lo más probable es que no haya ocurrido tráfico de ese tipo durante la ventana capturada — no es necesariamente un fallo de la tool. Para eventos poco frecuentes (una reconexión concreta), es más fiable capturar a PCAP con más duración (Capítulo 5) que repetir esta captura en vivo varias veces.

---

## Capítulo 5 — Captura y análisis de PCAP (5 tools)

A diferencia del capítulo anterior, aquí se graba el tráfico a un fichero para poder analizarlo después las veces que haga falta.

### `capturar_a_pcap(interfaz, segundos=30, filtro_captura="", nombre="")`

**Qué hace:** captura tráfico durante `segundos` y lo guarda en un `.pcap` en el host.

**Parámetros:**
- `interfaz`: interfaz en modo monitor (o cualquier interfaz de captura).
- `segundos`: duración (por defecto 30). Para un evento que puede tardar en darse (p. ej. "espera a que mi móvil se reconecte"), sube este valor con margen.
- `filtro_captura`: filtro BPF opcional a nivel de captura (p. ej. `"type mgt"` para solo management, o `"wlan host AA:BB:CC:DD:EE:FF"` para un solo dispositivo). Vacío = captura todo.
- `nombre`: nombre de fichero opcional; si no lo das, se genera automáticamente con fecha y hora.

**Cómo pedirlo:** "captura 60 segundos de tráfico en wlan1mon y guárdalo".

**Checkpoint:** la respuesta incluye el nombre del fichero generado, su tamaño y un resumen de paquetes. Si el tamaño es 0 o muy pequeño, no hubo tráfico en esa ventana — repite con más duración o confirma que el canal fijado es el correcto.

### `listar_pcaps()`

**Qué hace:** lista los ficheros `.pcap`/`.pcapng` ya guardados en el host, con tamaño y fecha.

**Cómo pedirlo:** "¿qué capturas pcap tengo guardadas?"

### `leer_pcap(nombre, modo="resumen", filtro="", max_lineas=100, descifrar=False)`

**Qué hace:** relee un PCAP ya capturado con distintos modos de análisis, sin tener que volver a capturar nada.

**Parámetros clave — `modo`:**
- `"resumen"`: lista de paquetes con protocolo e info, como se vería en la interfaz de Wireshark.
- `"protocolos"`: jerarquía de protocolos — qué hay dentro de la captura y en qué proporción.
- `"conversaciones"`: conversaciones agrupadas entre direcciones.
- `"campos"`: solo los campos 802.11 clave (origen, destino, BSSID, subtipo, SSID) — más compacto para revisar muchos paquetes rápido.
- `"crudo"`: aplica el `filtro` que le des y muestra la info de esos paquetes tal cual.

**Otros parámetros:**
- `filtro`: un display filter de Wireshark (p. ej. `"wlan.fc.type_subtype==0x0c"` para ver solo deauth), aplicable en modo `"crudo"` y `"campos"`.
- `max_lineas`: límite de salida para no saturar la respuesta (si se trunca, te lo dice explícitamente y sugiere afinar el filtro).
- `descifrar`: si `True`, intenta descifrar el tráfico WPA con las claves ya configuradas en el host (ver [Capítulo 7](#capítulo-7--descifrado-wpa-configurar-las-claves)) — **requiere que el PCAP contenga el 4-Way Handshake completo del cliente**; sin él no se puede derivar la clave de sesión y el tráfico unicast sigue viéndose cifrado.

**Cómo pedirlo:** "lee la captura 'captura_wlan1mon_20260910_120000.pcap' en modo protocolos" / "...aplica el filtro de deauth" / "...y descífrala".

**Nota conocida:** el modo `"wlan"` documentado en el código (estadísticas 802.11 vía `-z wlan,stat`) está roto en la versión de tshark instalada en este host (4.0.17) — no se ha corregido todavía. Usa `"protocolos"` o `"conversaciones"` en su lugar; ver "Problemas conocidos" al final de este capítulo.

### `analizar_ies_pcap(nombre, filtro_ssid="", filtro_bssid="")`

**Qué hace:** analiza los **beacons** de un PCAP y decodifica en detalle sus IEs (Information Elements — los bloques de capacidades que anuncia cada AP): generación WiFi, número de **flujos espaciales** (cuántas antenas puede usar a la vez para enviar/recibir varios "chorros" de datos en paralelo — más flujos, más velocidad potencial), anchos de canal soportados, **beamforming** (la capacidad de concentrar la señal de radio hacia un dispositivo concreto en vez de emitirla por igual en todas direcciones, para llegar más lejos y más limpio), y — muy importante para troubleshooting de auth — los parámetros **RSN** (cifrado, AKM, PMF) explicados en el [Capítulo 0.5](#rsn-akm-y-pmf-los-parámetros-de-seguridad-de-una-red).

**Perfila al AP** (lo que el punto de acceso ofrece). Su pareja es `perfilar_cliente_pcap`, que perfila al **cliente**.

Dos líneas de la salida merecen atención:

- **`Gen.`** — la generación WiFi, hasta **Wi-Fi 7 (802.11be)**. Distingue Wi-Fi 6 de Wi-Fi 6E (banda de 6 GHz) y detecta MLO, la capacidad de Wi-Fi 7 de usar varias bandas a la vez.
- **`Roam.`** — soporte de **roaming asistido**, la clave del "se queda pegado al AP lejano":
  - **802.11k** — el AP le pasa al cliente una lista de APs vecinos, para que no tenga que buscarlos a ciegas.
  - **802.11r** — *fast transition*: permite saltar de AP sin repetir el handshake entero (lo que se nota en llamadas de voz).
  - **802.11v** — el AP puede **sugerirle** al cliente que se cambie a otro AP mejor.

  Si los tres salen `NO`, la tool lo dice explícitamente: el cliente decide solo cuándo saltar, y ahí no hay nada que configurar en el AP. Ojo: para diagnosticar roaming hacen falta **las dos mitades** — el AP (aquí) y el cliente (`perfilar_cliente_pcap`). Basta con que una de las dos no lo soporte para que no haya roaming asistido.

**Parámetros:** `filtro_ssid` (parcial, no distingue mayúsculas) y `filtro_bssid` (exacto) para acotar a un AP concreto si el PCAP tiene beacons de varias redes.

**Cómo pedirlo:** "analiza los IEs de los beacons en 'captura_beacons.pcap', filtrando por SSID 'MiWifi'".

**Requisito silencioso:** esta tool depende de la librería `scapy` instalada en el entorno Python del host. Si no está, la respuesta lo dice explícitamente con la instrucción de instalación — no es un fallo de la captura, es un requisito de entorno.

### `perfilar_cliente_pcap(nombre, cliente_mac="", max_clientes=10)`

**Qué hace:** el espejo de la anterior. En vez de mirar qué ofrece el AP, mira **qué pide y qué sabe hacer el cliente**.

**De dónde saca la información:** cuando un dispositivo se une a una red envía una trama llamada *Association Request*, y en ella declara todo lo que sabe hacer. Si has capturado ese momento, ahí está el perfil completo del dispositivo sin necesidad de tocarlo ni instalarle nada.

**Qué te dice:**
- Generación WiFi soportada, flujos espaciales y anchos de canal (responde a "¿por qué este móvil nunca pasa de 80 MHz?").
- Soporte de **802.11k/r/v** — la otra mitad del diagnóstico de roaming.
- Bandas y canales que admite, y su potencia de transmisión mínima/máxima.
- Qué seguridad **pide** (AKM, cifrado, PMF), que no tiene por qué coincidir con la que ofrece el AP. Cuando no coinciden, ahí está el fallo de conexión.
- Si la MAC está **aleatorizada**.

**Sobre las MAC aleatorizadas.** Los móviles modernos se inventan una dirección MAC distinta por red, por privacidad. La consecuencia práctica: ves "dispositivos desconocidos" que en realidad son el mismo móvil de siempre, y no puedes identificarlo por su fabricante. La tool te avisa cuando ocurre (`MAC ALEATORIZADA`), para que no pierdas el tiempo buscando a quién pertenece. Cuando la MAC es real, te dice el fabricante.

**Parámetros:** `cliente_mac` para filtrar un dispositivo concreto; `max_clientes` para limitar cuántos reporta.

**Cómo pedirlo:** "perfila los clientes que se asocian en 'captura.pcap'".

**Requisito importante:** la captura tiene que contener **el momento de la asociación**. Hay que estar en modo monitor y en el canal del AP justo cuando el dispositivo se conecta. Si solo tienes beacons, esta tool no encontrará nada y te lo dirá — para beacons usa `analizar_ies_pcap`.

**Truco para provocarlo:** pon la captura en marcha y luego desactiva y reactiva el WiFi en el dispositivo. Así fuerzas la asociación dentro de la ventana capturada.

### Problemas conocidos (Capítulo 5)

- **`leer_pcap(modo="wlan")` da un error de tshark en vez de estadísticas.** Causa: el comando interno usa `-z wlan,stat`, que no es un nombre de estadística válido en tshark 4.0.17 (el nombre correcto sería `conv,wlan` o `endpoints,wlan`). Pendiente de corregir en el código. Mientras tanto, usa `modo="protocolos"` o `modo="conversaciones"`.
- **`descifrar=True` no cambia nada, sigue viéndose "QoS Data" cifrado.** Causa más probable: el PCAP no contiene el 4-Way Handshake completo del cliente (sin M1-M4 no hay forma de derivar la clave de sesión). Solución: recaptura cubriendo el momento exacto en que el cliente se reconecta a la red, o usa `diagnosticar_conectividad_cliente` (Capítulo 6), que ya comprueba esto explícitamente y te lo dice en vez de devolver un resultado vacío engañoso.

---

## Capítulo 6 — Diagnóstico combinado: el atajo recomendado (3 tools)

Estas tres tools no están en el prompt original de la skill de análisis WiFi del proyecto — se añadieron después para cubrir directamente los dos casos de troubleshooting más habituales sin tener que encadenar varias tools a mano. **Para el uso normal del día a día, empieza siempre por aquí antes de bajar al detalle de los Capítulos 4/5.**

### `diagnosticar_autenticacion(interfaz, paquetes=30)`

**Qué hace:** combina en una sola pasada `capturar_autenticacion` + `capturar_eapol` (Capítulo 4) y añade un **veredicto automático**: detecta timeout del 4-Way Handshake, fallo de autenticación 802.1X, o timeout del Group Key Handshake, con una recomendación de por dónde seguir mirando en cada caso.

**Cuándo usarlo:** es la tool por defecto para "este dispositivo no consigue conectarse al WiFi" — cubre todo lo que pasa **antes** de que el cliente quede asociado.

**Requisito previo:** la interfaz debe estar ya en modo monitor y en el canal correcto (Capítulo 2).

**Cómo pedirlo:** "diagnostica por qué mi portátil no consigue autenticarse en la red X, en wlan1mon".

**Checkpoint:** si el veredicto dice "sin patrones de fallo reconocidos", no significa que no haya problema — significa que no ocurrió ningún evento de auth/EAPOL durante la ventana capturada (súbele el número de `paquetes`, o provoca tú el intento de conexión mientras la captura está en marcha).

### `diagnosticar_conectividad_cliente(nombre, cliente_mac="", max_lineas=40)`

**Qué hace:** el equivalente de la anterior pero para **después** de la asociación — el caso "el dispositivo se conecta al WiFi pero no navega". Sobre un PCAP ya capturado, descifra el tráfico WPA y revisa DHCP (¿le dieron IP?), ARP (¿resuelve su puerta de enlace?) y DNS (¿resuelve nombres?), con un veredicto de en qué punto exacto se corta la cadena.

**Parámetros:**
- `nombre`: el fichero PCAP (ver `listar_pcaps`).
- `cliente_mac`: opcional, para acotar a un dispositivo concreto (formato `aa:bb:cc:dd:ee:ff`); vacío analiza todo el PCAP.

**Requisito previo — sin este paso la tool no puede hacer nada:** necesita claves WPA ya configuradas en el host (ver [Capítulo 7](#capítulo-7--descifrado-wpa-configurar-las-claves)) **y** que el PCAP contenga el 4-Way Handshake completo del cliente en cuestión.

**Flujo recomendado completo:**
```
activar_modo_monitor(iw) → fijar_canal → capturar_a_pcap (cubriendo la reconexión
del cliente) → diagnosticar_conectividad_cliente(fichero, mac_cliente)
```

**Cómo pedirlo:** "mi móvil se conecta a la red pero no tiene internet; captura su reconexión y diagnostica qué pasa".

**Checkpoint:** la primera sección de la respuesta ("Estado del descifrado") te dice si el descifrado surtió efecto antes de intentar interpretar nada de DHCP/ARP/DNS. Si dice "descifrado SIN efecto", no sigas leyendo el resto — soluciona primero esa causa (normalmente: falta el handshake en el PCAP, o la clave configurada no es la correcta).

### `estado_descifrado_wpa()`

**Qué hace:** verifica si el descifrado WPA está configurado en el host — si existe el fichero de claves, si tiene los permisos correctos, y qué claves contiene (tipo y SSID; **el material de clave en sí nunca se muestra**, solo se enmascara con su longitud). No revela ni acepta contraseñas — solo diagnostica el estado.

**Cuándo usarlo:** antes de intentar `descifrar=True` en `leer_pcap` o antes de `diagnosticar_conectividad_cliente`, si no estás seguro de si ya hay claves cargadas.

**Cómo pedirlo:** "¿está configurado el descifrado WPA en el servidor?"

---

## Capítulo 7 — Descifrado WPA: configurar las claves

**Por qué esto no es una tool más:** deliberadamente, no existe ninguna tool para dar de alta una contraseña WPA. Si lo fuera, la contraseña quedaría escrita en la conversación con Claude y en los logs del cliente MCP — un riesgo de seguridad innecesario. En su lugar, las claves se crean **a mano, directamente en el host, por SSH** — una acción administrativa puntual, fuera del flujo normal descrito en el resto de esta guía.

**Antes de tocar nada: backup.** Si el fichero de claves ya existe y solo quieres añadir una red nueva, haz una copia antes de sobreescribir:
```bash
ssh usuario@10.10.1.142 "cp ~/mcp_tshark/wireshark_profile/80211_keys ~/mcp_tshark/wireshark_profile/80211_keys.bak_$(date +%Y%m%d_%H%M%S) 2>/dev/null; echo hecho"
```
*(Esto se ejecuta desde tu propio ordenador — es un comando SSH que actúa sobre el host remoto.)*

**Crear o añadir una clave** *(mismo sitio: tu ordenador, actuando por SSH sobre el host)*:
```bash
ssh usuario@10.10.1.142 "umask 077 && printf '%s\n' '\"wpa-pwd\",\"MI_PASSPHRASE:MI_SSID\"' >> ~/mcp_tshark/wireshark_profile/80211_keys"
```
Sustituye `MI_PASSPHRASE` por la contraseña real de la red y `MI_SSID` por su nombre. `umask 077` asegura que el fichero se cree con permisos `600` (solo lectura/escritura para el propio usuario) desde el primer momento.

**Formato del fichero** (una línea por red, en **UAT** — el formato de tabla con el que Wireshark guarda listas de credenciales, en este caso una lista de claves de descifrado):
- `"wpa-pwd","passphrase:SSID"` — passphrase en texto claro. El SSID es opcional (si falta, se usa el de la propia captura), pero conviene ponerlo si vas a tener varias redes en el mismo fichero.
- `"wpa-psk","<64 caracteres hex>"` — si ya tienes la **PMK** derivada en vez de la passphrase (la PMK es la clave intermedia de 256 bits que sale de combinar la passphrase con el SSID mediante un algoritmo estándar — con este formato se la das ya calculada en vez de dejar que tshark la derive él mismo).
- `"wep","<hex>"` — WEP, obsoleto, solo por completitud.

**Checkpoint:** después de crear/editar el fichero, pídele a Claude que ejecute `estado_descifrado_wpa()`. Debe mostrar la red recién añadida (SSID visible, passphrase enmascarada) y **ninguna línea marcada como inválida**.

### Problemas conocidos (Capítulo 7)

- **Una sola línea mal formada deja el descifrado desactivado por completo, sin avisar por su cuenta.** Comprobado: tshark rechaza la tabla entera de claves si una sola línea no cumple el formato exacto (comillas, comas), no solo esa línea. Por eso `estado_descifrado_wpa()` te avisa explícitamente de qué números de línea tienen formato inválido — revísalos y corrígelos antes de asumir que el descifrado "debería" estar funcionando.
- **El SSID se separa por el último `:` de la línea, no el primero.** Si tu passphrase contuviera un carácter `:` (poco común, pero posible), asegúrate de que el SSID va siempre al final para que el separado sea correcto.
- **WPA3-SAE no es descifrable con este mecanismo.** Si la red usa SAE (WPA3-Personal puro, sin modo de transición), la passphrase no sirve para derivar la clave de sesión de la misma forma que en WPA2-PSK — `diagnosticar_conectividad_cliente` lo señala como una de las causas posibles cuando el descifrado no surte efecto pese a haber handshake.

---

## Capítulo 8 — Flujos completos de ejemplo (recetas end-to-end)

### A) "Este dispositivo no consigue conectarse a la red"

1. `listar_interfaces()` — confirma que `wlan1` está libre.
2. Si no sabes el canal de la red: `escanear_ssid(interfaz="wlan0", ssid="NOMBRE_RED")` — anota el canal.
3. `activar_modo_monitor(interfaz="wlan1", metodo="iw")`.
4. `fijar_canal(interfaz="wlan1mon", canal=<el que anotaste>, ancho="HT20")`.
5. Provoca (o espera) el intento de conexión del dispositivo problemático.
6. `diagnosticar_autenticacion(interfaz="wlan1mon", paquetes=30)` — lee el veredicto.
7. Al terminar: `desactivar_modo_monitor(interfaz="wlan1mon", metodo="iw")`.

### B) "Se conecta pero no navega"

1-4. Igual que el flujo A.
5. `estado_descifrado_wpa()` — confirma que la red en cuestión ya tiene clave configurada (si no, ver Capítulo 7 primero).
6. `capturar_a_pcap(interfaz="wlan1mon", segundos=60, nombre="conectividad_cliente.pcap")` mientras el dispositivo se reconecta de verdad (para capturar su 4-Way Handshake).
7. `diagnosticar_conectividad_cliente(nombre="conectividad_cliente.pcap", cliente_mac="aa:bb:cc:dd:ee:ff")` — lee el veredicto (DHCP/ARP/DNS).
8. Al terminar: `desactivar_modo_monitor(interfaz="wlan1mon", metodo="iw")`.

### C) "¿Qué capacidades WiFi tienen los puntos de acceso alrededor?"

**Camino corto (recomendado) — sin modo monitor, todas las bandas:**

1. `escanear_a_pcap(interfaz="wlan0", nombre="survey.pcap")`
2. `analizar_ies_pcap(nombre="survey.pcap")`

Dos pasos, sin tocar el modo monitor y cubriendo 2.4 y 5 GHz de una pasada. Requiere `scandump` instalado.

**Camino largo (si `scandump` no está disponible):**

1. `capturar_a_pcap(interfaz="wlan1", segundos=30, nombre="beacons_survey.pcap")` (con la interfaz ya en modo monitor y canal fijado, como en el flujo A, pasos 1-4).
2. `analizar_ies_pcap(nombre="beacons_survey.pcap")`

Ojo: esto solo ve **el canal que hayas fijado**. Para cubrir varios hay que repetirlo canal por canal.

### D) "Se queda pegado a un AP lejano y no salta al cercano"

El roaming asistido necesita que **AP y cliente** lo soporten. Hay que mirar las dos mitades:

1. `escanear_a_pcap(interfaz="wlan0", nombre="roam.pcap")` y `analizar_ies_pcap(nombre="roam.pcap")` → línea `Roam.` de cada AP.
2. Con `wlan1` en monitor en el canal del AP, `capturar_a_pcap` mientras fuerzas la reconexión del dispositivo (desactiva y reactiva su WiFi).
3. `perfilar_cliente_pcap(nombre="...")` → línea `Roaming` del cliente.

**Cómo leerlo:** si el AP dice `802.11v=si` pero el cliente dice `802.11v=NO`, el AP no puede sugerirle el cambio y el cliente decide solo — no hay nada que tocar en la configuración del AP. Si ambos dicen `NO`, no hay roaming asistido en absoluto.

**Límite honesto:** esto te dice si el roaming asistido es *posible*. Medir el tiempo real del salto entre APs es la Fase 2 del roadmap, todavía sin implementar.

---

## Apéndice — Tabla resumen de las 27 tools

| # | Tool | Capítulo |
|---|---|---|
| 1 | `listar_interfaces` | 1 |
| 2 | `info_interfaz` | 1 |
| 3 | `capacidades_phy` | 1 |
| 4 | `activar_modo_monitor` | 2 |
| 5 | `desactivar_modo_monitor` | 2 |
| 6 | `fijar_canal` | 2 |
| 7 | `survey_canales` | 3 |
| 8 | `escanear_redes` | 3 |
| 9 | `escanear_ssid` | 3 |
| 10 | `escanear_a_pcap` | 3 |
| 11 | `capturar_beacons` | 4 |
| 12 | `capturar_probe_requests` | 4 |
| 13 | `capturar_autenticacion` | 4 |
| 14 | `capturar_asociacion` | 4 |
| 15 | `capturar_eapol` | 4 |
| 16 | `capturar_management` | 4 |
| 17 | `capturar_control` | 4 |
| 18 | `capturar_datos` | 4 |
| 19 | `estadisticas_wlan` | 4 |
| 20 | `capturar_a_pcap` | 5 |
| 21 | `listar_pcaps` | 5 |
| 22 | `leer_pcap` | 5 |
| 23 | `analizar_ies_pcap` | 5 |
| 24 | `perfilar_cliente_pcap` | 5 |
| 25 | `diagnosticar_autenticacion` | 6 |
| 26 | `diagnosticar_conectividad_cliente` | 6 |
| 27 | `estado_descifrado_wpa` | 6 |

**Nota sobre el alcance de esta guía:** cubre las 27 tools tal como existen hoy en `tshark_server.py` (verificado contra el código fuente real). Las capacidades de Fase 3 (interferencia RF con % de utilización/SNR) y Fase 4 (persistencia/histórico entre sesiones) descritas en `ROADMAP.md` **todavía no están implementadas**. De la Fase 2 (roaming) ya está hecha la parte de capacidades 802.11k/r/v en AP y cliente (receta D), pero **no** la medición del tiempo real del salto entre APs — cuando lo esté, esta guía deberá ampliarse.
