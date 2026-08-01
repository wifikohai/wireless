import subprocess
import re
import os
import glob
import struct
from datetime import datetime
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Tshark-WiFi-Ubuntu", host="0.0.0.0", port=8000)

# ---------------------------------------------------------------------------
# Configuracion
# ---------------------------------------------------------------------------

# Directorio donde se guardan las capturas .pcap
PCAP_DIR = os.path.expanduser("~/mcp_tshark/capturas")
os.makedirs(PCAP_DIR, exist_ok=True)

INTERFACES_PERMITIDAS = []  # p.ej. ["wlan0", "wlan0mon"]
NOMBRE_VALIDO = re.compile(r"^[a-zA-Z0-9_.-]{1,20}$")
# Nombre de fichero pcap seguro: solo letras, numeros, _ - . y termina en .pcap/.pcapng
PCAP_VALIDO = re.compile(r"^[a-zA-Z0-9_.-]{1,80}\.(pcap|pcapng)$")


def _validar_interfaz(iface: str) -> str | None:
    if not NOMBRE_VALIDO.match(iface):
        return f"Nombre de interfaz no valido: '{iface}'."
    if INTERFACES_PERMITIDAS and iface not in INTERFACES_PERMITIDAS:
        return f"Interfaz '{iface}' no esta en la lista de permitidas: {INTERFACES_PERMITIDAS}"
    return None


def _ruta_pcap_segura(nombre: str) -> tuple[str | None, str | None]:
    """Valida el nombre de pcap y devuelve (ruta_absoluta, None) o (None, error)."""
    if not PCAP_VALIDO.match(nombre):
        return None, f"Nombre de pcap no valido: '{nombre}'. Debe ser algo como 'captura.pcap'."
    ruta = os.path.join(PCAP_DIR, nombre)
    # Evita path traversal: la ruta resuelta debe estar dentro de PCAP_DIR
    if os.path.commonpath([os.path.realpath(ruta), os.path.realpath(PCAP_DIR)]) != os.path.realpath(PCAP_DIR):
        return None, "Ruta fuera del directorio de capturas."
    return ruta, None


def _run(comando: list, timeout: int = 30, usar_sudo: bool = False) -> str:
    if usar_sudo:
        comando = ["sudo", "-n"] + comando
    try:
        r = subprocess.run(comando, capture_output=True, text=True, timeout=timeout)
        salida = r.stdout.strip()
        if r.stderr.strip():
            salida += ("\n[stderr] " + r.stderr.strip()) if salida else ("[stderr] " + r.stderr.strip())
        return salida or "(sin salida)"
    except subprocess.TimeoutExpired:
        return f"Timeout tras {timeout}s ejecutando: {' '.join(comando)}"
    except FileNotFoundError:
        return f"Comando no encontrado: {comando[0]}. Instalalo (apt install iw aircrack-ng tshark)."
    except Exception as e:
        return f"Error: {str(e)}"


# ---------------------------------------------------------------------------
# 1. Descubrimiento e informacion
# ---------------------------------------------------------------------------

@mcp.tool()
def listar_interfaces() -> str:
    """Lista todas las interfaces de red y sus interfaces WiFi con detalle (tipo, modo, canal)."""
    salida = "=== Interfaces de captura (tshark -D) ===\n"
    salida += _run(["tshark", "-D"], timeout=10)
    salida += "\n\n=== Interfaces WiFi (iw dev) ===\n"
    salida += _run(["iw", "dev"], timeout=10)
    return salida


@mcp.tool()
def info_interfaz(interfaz: str) -> str:
    """Muestra informacion detallada de una interfaz WiFi: modo actual, canal, potencia, tipo.

    interfaz: nombre de la interfaz (ej: 'wlan0').
    """
    err = _validar_interfaz(interfaz)
    if err:
        return err
    salida = f"=== iw dev {interfaz} info ===\n"
    salida += _run(["iw", "dev", interfaz, "info"], timeout=10)
    return salida


@mcp.tool()
def capacidades_phy() -> str:
    """Lista las capacidades fisicas de los adaptadores WiFi: bandas, canales, anchos (HT/VHT/HE)."""
    return _run(["iw", "phy"], timeout=15)


# ---------------------------------------------------------------------------
# 2. Gestion de modo monitor
# ---------------------------------------------------------------------------

@mcp.tool()
def activar_modo_monitor(interfaz: str, metodo: str = "airmon") -> str:
    """Pone una interfaz WiFi en modo monitor.

    interfaz: interfaz base (ej: 'wlan0').
    metodo: 'airmon' (recomendado, crea wlan0mon) o 'iw' (manual).
    """
    err = _validar_interfaz(interfaz)
    if err:
        return err

    if metodo == "airmon":
        import time
        salida = f"=== airmon-ng stop {interfaz} ===\n"
        salida += _run(["airmon-ng", "stop", interfaz], timeout=20, usar_sudo=True)
        # Levantar explicitamente la interfaz base
        iface_base = interfaz.replace("mon", "")
        salida += f"\n\n=== Levantar {iface_base} ===\n"
        salida += _run(["ip", "link", "set", iface_base, "up"], usar_sudo=True)
        time.sleep(5)
        salida += "\n\n=== Reiniciar NetworkManager ===\n"
        salida += _run(["systemctl", "restart", "NetworkManager"], timeout=20, usar_sudo=True)
        time.sleep(8)
    elif metodo == "iw":
        pasos = []
        pasos.append(("ip link down", _run(["ip", "link", "set", interfaz, "down"], usar_sudo=True)))
        pasos.append(("iw set monitor", _run(["iw", interfaz, "set", "monitor", "control"], usar_sudo=True)))
        pasos.append(("ip link up", _run(["ip", "link", "set", interfaz, "up"], usar_sudo=True)))
        salida = "\n".join(f"=== {n} ===\n{r}" for n, r in pasos)
        salida += f"\n\n=== Verificacion ===\n" + _run(["iw", "dev", interfaz, "info"], timeout=10)
        return salida
    else:
        return "Metodo no valido. Usa 'airmon' o 'iw'."


@mcp.tool()
def desactivar_modo_monitor(interfaz: str, metodo: str = "airmon") -> str:
    """Devuelve una interfaz de modo monitor a modo managed.

    interfaz: interfaz monitor (ej: 'wlan0mon' o 'wlan0').
    metodo: 'airmon' o 'iw'. Debe coincidir con el usado para activarlo.
    """
    err = _validar_interfaz(interfaz)
    if err:
        return err

    if metodo == "airmon":
        import time
        salida = f"=== airmon-ng stop {interfaz} ===\n"
        salida += _run(["airmon-ng", "stop", interfaz], timeout=20, usar_sudo=True)
        iface_base = interfaz.replace("mon", "")
        salida += f"\n\n=== Levantar {iface_base} ===\n"
        salida += _run(["ip", "link", "set", iface_base, "up"], usar_sudo=True)
        time.sleep(8)
        salida += "\n\n=== Reiniciar NetworkManager ===\n"
        salida += _run(["systemctl", "restart", "NetworkManager"], timeout=20, usar_sudo=True)
        time.sleep(5)
        return salida
    elif metodo == "iw":
        pasos = []
        pasos.append(("ip link down", _run(["ip", "link", "set", interfaz, "down"], usar_sudo=True)))
        pasos.append(("iw set managed", _run(["iw", interfaz, "set", "type", "managed"], usar_sudo=True)))
        pasos.append(("ip link up", _run(["ip", "link", "set", interfaz, "up"], usar_sudo=True)))
        return "\n".join(f"=== {n} ===\n{r}" for n, r in pasos)
    else:
        return "Metodo no valido. Usa 'airmon' o 'iw'."


# ---------------------------------------------------------------------------
# 3. Fijar canal y ancho de banda
# ---------------------------------------------------------------------------

@mcp.tool()
def fijar_canal(interfaz: str, canal: int, ancho: str = "HT20") -> str:
    """Fija el canal y el ancho de banda de una interfaz en modo monitor.

    interfaz: interfaz monitor (ej: 'wlan0mon').
    canal: numero de canal (2.4GHz:1-13; 5GHz:36..165; 6GHz:1-233).
    ancho: 'HT20'(20MHz), 'HT40+'/'HT40-'(40MHz), '80MHz', '160MHz', '5MHz', '10MHz'.
    """
    err = _validar_interfaz(interfaz)
    if err:
        return err
    anchos_validos = {"HT20", "HT40+", "HT40-", "80MHz", "160MHz", "5MHz", "10MHz", "20MHz"}
    if ancho not in anchos_validos:
        return f"Ancho no valido: '{ancho}'. Validos: {sorted(anchos_validos)}"
    if ancho in {"HT20", "HT40+", "HT40-", "20MHz"}:
        ancho_iw = "HT20" if ancho == "20MHz" else ancho
        salida = _run(["iw", "dev", interfaz, "set", "channel", str(canal), ancho_iw], usar_sudo=True)
    else:
        salida = _run(["iw", "dev", interfaz, "set", "channel", str(canal), ancho], usar_sudo=True)
    salida += "\n\n=== Verificacion ===\n"
    salida += _run(["iw", "dev", interfaz, "info"], timeout=10)
    return salida


# ---------------------------------------------------------------------------
# 4. Captura filtrada en vivo (a texto)
# ---------------------------------------------------------------------------

def _captura_wlan(interfaz: str, display_filter: str, paquetes: int,
                  campos: list, timeout_extra: int = 15) -> str:
    err = _validar_interfaz(interfaz)
    if err:
        return err
    comando = ["tshark", "-i", interfaz, "-c", str(paquetes), "-Y", display_filter, "-T", "fields"]
    for c in campos:
        comando += ["-e", c]
    comando += ["-E", "separator=|"]
    return _run(comando, timeout=paquetes + timeout_extra, usar_sudo=True)


@mcp.tool()
def capturar_management(interfaz: str, paquetes: int = 20) -> str:
    """Captura frames MANAGEMENT (beacons, probe, assoc, auth, deauth...)."""
    campos = ["frame.time_relative", "wlan.sa", "wlan.da", "wlan.bssid",
              "wlan.fc.type_subtype", "wlan.ssid", "radiotap.channel.freq"]
    return _captura_wlan(interfaz, "wlan.fc.type==0", paquetes, campos)


@mcp.tool()
def capturar_asociacion(interfaz: str, paquetes: int = 20) -> str:
    """Captura frames de ASOCIACION y reasociacion."""
    df = ("wlan.fc.type_subtype==0x00 or wlan.fc.type_subtype==0x01 or "
          "wlan.fc.type_subtype==0x02 or wlan.fc.type_subtype==0x03")
    campos = ["frame.time_relative", "wlan.sa", "wlan.da", "wlan.bssid",
              "wlan.fc.type_subtype", "wlan.ssid", "wlan.fixed.status_code"]
    return _captura_wlan(interfaz, df, paquetes, campos)


@mcp.tool()
def capturar_autenticacion(interfaz: str, paquetes: int = 20) -> str:
    """Captura frames de AUTENTICACION y desautenticacion (auth, deauth, disassoc)."""
    df = ("wlan.fc.type_subtype==0x0b or wlan.fc.type_subtype==0x0c or "
          "wlan.fc.type_subtype==0x0a")
    campos = ["frame.time_relative", "wlan.sa", "wlan.da", "wlan.bssid",
              "wlan.fc.type_subtype", "wlan.fixed.auth.alg", "wlan.fixed.reason_code"]
    return _captura_wlan(interfaz, df, paquetes, campos)


@mcp.tool()
def capturar_datos(interfaz: str, paquetes: int = 20) -> str:
    """Captura frames de tipo DATA (trafico de datos real)."""
    campos = ["frame.time_relative", "wlan.sa", "wlan.da", "wlan.bssid",
              "wlan.fc.type_subtype", "frame.len", "radiotap.datarate"]
    return _captura_wlan(interfaz, "wlan.fc.type==2", paquetes, campos)


@mcp.tool()
def capturar_control(interfaz: str, paquetes: int = 20) -> str:
    """Captura frames de tipo CONTROL (ACK, RTS, CTS, Block-ACK...)."""
    campos = ["frame.time_relative", "wlan.ta", "wlan.ra",
              "wlan.fc.type_subtype", "radiotap.dbm_antsignal"]
    return _captura_wlan(interfaz, "wlan.fc.type==1", paquetes, campos)


@mcp.tool()
def capturar_beacons(interfaz: str, paquetes: int = 30) -> str:
    """Captura frames BEACON: SSID, BSSID, canal y capacidades (survey pasivo)."""
    campos = ["wlan.sa", "wlan.ssid", "wlan.ds.current_channel",
              "radiotap.channel.freq", "radiotap.dbm_antsignal"]
    return _captura_wlan(interfaz, "wlan.fc.type_subtype==0x08", paquetes, campos)


@mcp.tool()
def capturar_eapol(interfaz: str, paquetes: int = 20) -> str:
    """Captura frames EAPOL (handshake WPA/WPA2/WPA3 4-way)."""
    campos = ["frame.time_relative", "wlan.sa", "wlan.da",
              "eapol.type", "eapol.keydes.key_info"]
    return _captura_wlan(interfaz, "eapol", paquetes, campos)


@mcp.tool()
def capturar_probe_requests(interfaz: str, paquetes: int = 30) -> str:
    """Captura PROBE REQUESTS: que clientes buscan y que SSIDs solicitan."""
    campos = ["frame.time_relative", "wlan.sa", "wlan.ssid",
              "radiotap.dbm_antsignal"]
    return _captura_wlan(interfaz, "wlan.fc.type_subtype==0x04", paquetes, campos)


# ---------------------------------------------------------------------------
# 5. Captura a fichero PCAP + gestion + lectura
# ---------------------------------------------------------------------------

@mcp.tool()
def capturar_a_pcap(interfaz: str, segundos: int = 30, filtro_captura: str = "",
                    nombre: str = "") -> str:
    """Captura trafico durante N segundos y lo guarda en un fichero .pcap para analisis posterior.

    interfaz: interfaz en modo monitor (ej: 'wlan0mon') o cualquier interfaz de captura.
    segundos: duracion de la captura en segundos (por defecto 30).
    filtro_captura: filtro BPF opcional a nivel de captura (ej: 'type mgt', 'wlan host AA:BB:...').
                    Dejar vacio para capturar todo.
    nombre: nombre de fichero opcional. Si se omite, se genera con timestamp.

    Devuelve el nombre del fichero generado y un resumen basico. Usa 'leer_pcap' o
    'listar_pcaps' despues para analizarlo.
    """
    err = _validar_interfaz(interfaz)
    if err:
        return err

    if nombre:
        if not PCAP_VALIDO.match(nombre):
            return f"Nombre no valido: '{nombre}'. Usa algo como 'mi_captura.pcap'."
        fichero = nombre
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fichero = f"captura_{interfaz}_{ts}.pcap"

    ruta, err = _ruta_pcap_segura(fichero)
    if err:
        return err

    comando = ["tshark", "-i", interfaz, "-a", f"duration:{segundos}", "-w", ruta]
    if filtro_captura:
        comando += ["-f", filtro_captura]

    # timeout = duracion + margen amplio
    resultado = _run(comando, timeout=segundos + 30, usar_sudo=True)

    if not os.path.exists(ruta):
        return f"No se genero el fichero. Salida de tshark:\n{resultado}"

    tam = os.path.getsize(ruta)
    # Cuenta rapida de paquetes
    conteo = _run(["tshark", "-r", ruta, "-q", "-z", "io,stat,0"], timeout=30, usar_sudo=True)
    return (f"Captura guardada: {fichero}\n"
            f"Ruta: {ruta}\n"
            f"Tamano: {tam} bytes\n"
            f"Duracion: {segundos}s | Filtro: {filtro_captura or '(ninguno)'}\n\n"
            f"=== Resumen (io,stat) ===\n{conteo}\n\n"
            f"Usa leer_pcap('{fichero}') para analizarlo en detalle.")


@mcp.tool()
def listar_pcaps() -> str:
    """Lista los ficheros .pcap disponibles en el directorio de capturas, con tamano y fecha."""
    ficheros = sorted(glob.glob(os.path.join(PCAP_DIR, "*.pcap")) +
                      glob.glob(os.path.join(PCAP_DIR, "*.pcapng")),
                      key=os.path.getmtime, reverse=True)
    if not ficheros:
        return f"No hay capturas en {PCAP_DIR}. Genera una con capturar_a_pcap."
    salida = f"=== Capturas en {PCAP_DIR} ===\n"
    for f in ficheros:
        tam = os.path.getsize(f)
        mtime = datetime.fromtimestamp(os.path.getmtime(f)).strftime("%Y-%m-%d %H:%M:%S")
        salida += f"{os.path.basename(f):<45} | {tam:>10} bytes | {mtime}\n"
    return salida


@mcp.tool()
def leer_pcap(nombre: str, modo: str = "resumen", filtro: str = "", max_lineas: int = 100) -> str:
    """Lee y analiza un fichero .pcap ya capturado, con distintos modos de analisis.

    nombre: nombre del fichero pcap (ej: 'captura_wlan0mon_20260710_160000.pcap').
            Usa listar_pcaps() para ver los disponibles.
    modo: tipo de analisis:
        - 'resumen'      -> lista de paquetes con protocolo e info (como Wireshark)
        - 'protocolos'   -> jerarquia de protocolos (io,phs): que hay en la captura
        - 'wlan'         -> estadisticas 802.11 por tipo/subtipo (wlan,stat)
        - 'conversaciones' -> conversaciones entre direcciones
        - 'campos'       -> campos 802.11 clave (sa, da, bssid, subtipo, ssid)
        - 'crudo'        -> aplica el 'filtro' dado y muestra info de esos paquetes
    filtro: display filter de Wireshark opcional (ej: 'wlan.fc.type_subtype==0x0c' para deauth).
            Se aplica en modo 'crudo' y 'campos'.
    max_lineas: limite de lineas de salida (para no saturar).
    """
    ruta, err = _ruta_pcap_segura(nombre)
    if err:
        return err
    if not os.path.exists(ruta):
        return f"No existe el fichero '{nombre}'. Usa listar_pcaps() para ver los disponibles."

    if modo == "resumen":
        comando = ["tshark", "-r", ruta]
        if filtro:
            comando += ["-Y", filtro]
    elif modo == "protocolos":
        comando = ["tshark", "-r", ruta, "-q", "-z", "io,phs"]
    elif modo == "wlan":
        comando = ["tshark", "-r", ruta, "-q", "-z", "wlan,stat"]
    elif modo == "conversaciones":
        comando = ["tshark", "-r", ruta, "-q", "-z", "conv,wlan"]
    elif modo == "campos":
        comando = ["tshark", "-r", ruta]
        if filtro:
            comando += ["-Y", filtro]
        comando += ["-T", "fields",
                    "-e", "frame.time_relative", "-e", "wlan.sa", "-e", "wlan.da",
                    "-e", "wlan.bssid", "-e", "wlan.fc.type_subtype", "-e", "wlan.ssid",
                    "-E", "separator=|"]
    elif modo == "crudo":
        comando = ["tshark", "-r", ruta]
        if filtro:
            comando += ["-Y", filtro]
    else:
        return ("Modo no valido. Usa: 'resumen', 'protocolos', 'wlan', "
                "'conversaciones', 'campos' o 'crudo'.")

    salida = _run(comando, timeout=60, usar_sudo=True)

    # Limita numero de lineas para no saturar la respuesta
    lineas = salida.split("\n")
    if len(lineas) > max_lineas:
        salida = "\n".join(lineas[:max_lineas])
        salida += f"\n\n... [salida truncada a {max_lineas} lineas de {len(lineas)} totales. "
        salida += "Usa un 'filtro' mas especifico o aumenta max_lineas.]"
    return salida


# ---------------------------------------------------------------------------
# 6. Analisis / escaneo
# ---------------------------------------------------------------------------

@mcp.tool()
def survey_canales(interfaz: str) -> str:
    """Survey de canales (iw survey dump): ruido y ocupacion por canal."""
    err = _validar_interfaz(interfaz)
    if err:
        return err
    return _run(["iw", "dev", interfaz, "survey", "dump"], timeout=15, usar_sudo=True)


@mcp.tool()
def escanear_redes(interfaz: str) -> str:
    """Escanea redes WiFi visibles (iw scan). Requiere interfaz en modo managed."""
    err = _validar_interfaz(interfaz)
    if err:
        return err
    salida = _run(["iw", "dev", interfaz, "scan"], timeout=20, usar_sudo=True)
    if len(salida) > 6000:
        lineas = salida.split("\n")
        filtradas = [l for l in lineas if any(k in l for k in
                     ["BSS ", "SSID:", "signal:", "freq:", "RSN:", "WPA:", "DS Parameter"])]
        return "(salida resumida)\n" + "\n".join(filtradas)
    return salida


def _freq_a_canal(freq: str) -> str:
    try:
        f = int(freq)
        if f == 2484:
            return "14"
        if 2412 <= f <= 2472:
            return str((f - 2407) // 5)
        if 5000 <= f <= 5900:
            return str((f - 5000) // 5)
        if 5955 <= f <= 7115:
            return str((f - 5950) // 5)
    except (ValueError, TypeError):
        pass
    return "?"


@mcp.tool()
def escanear_ssid(interfaz: str = "wlan0", ssid: str = "") -> str:
    """Escanea redes WiFi y muestra BSSID, canal, frecuencia y senal de cada AP.
    Si se indica un SSID, filtra solo por esa red.

    interfaz: interfaz WiFi en modo managed (ej: 'wlan0').
    ssid: nombre de red a filtrar. Vacio = todas.
    """
    err = _validar_interfaz(interfaz)
    if err:
        return err
    salida = _run(["iw", "dev", interfaz, "scan"], timeout=25, usar_sudo=True)
    if salida.startswith(("Error", "Timeout", "Comando no encontrado")):
        return salida

    redes, actual = [], {}
    for linea in salida.split("\n"):
        l = linea.strip()
        if l.startswith("BSS "):
            if actual:
                redes.append(actual)
            actual = {"bssid": l.split()[1].split("(")[0], "ssid": "", "freq": "",
                      "signal": "", "canal": "", "seguridad": ""}
        elif l.startswith("freq:"):
            actual["freq"] = l.split(":", 1)[1].strip()
        elif l.startswith("signal:"):
            actual["signal"] = l.split(":", 1)[1].strip()
        elif l.startswith("SSID:"):
            actual["ssid"] = l.split("SSID:", 1)[1].strip()
        elif "primary channel:" in l:
            actual["canal"] = l.split("primary channel:", 1)[1].strip()
        elif l.startswith("DS Parameter set: channel"):
            actual["canal"] = l.split("channel", 1)[1].strip()
        elif l.startswith("RSN:"):
            actual["seguridad"] = "WPA2/WPA3"
        elif l.startswith("WPA:") and not actual.get("seguridad"):
            actual["seguridad"] = "WPA"
    if actual:
        redes.append(actual)

    if ssid:
        redes = [r for r in redes if r.get("ssid") == ssid]
        if not redes:
            return f"No se encontro ninguna red con SSID '{ssid}' (sensible a mayusculas)."
    if not redes:
        return "No se detecto ninguna red."

    def _clave(r):
        try:
            return int(r.get("freq", "0"))
        except (ValueError, TypeError):
            return 0

    out = [f"=== Redes{f' con SSID={ssid}' if ssid else ''}: {len(redes)} ==="]
    for r in sorted(redes, key=_clave):
        canal = r.get("canal") or _freq_a_canal(r.get("freq", ""))
        nombre = r["ssid"] or "(oculto)"
        seg = r.get("seguridad") or "abierta/?"
        out.append(f"SSID: {nombre:<20} | BSSID: {r['bssid']} | Canal: {canal:<4} | "
                   f"Freq: {r['freq']} MHz | Senal: {r['signal']} dBm | Seg: {seg}")
    return "\n".join(out)


@mcp.tool()
def estadisticas_wlan(interfaz: str, segundos: int = 15) -> str:
    """Captura N segundos en modo monitor y da estadisticas 802.11 por tipo/subtipo."""
    import time, tempfile
    from collections import Counter
    err = _validar_interfaz(interfaz)
    if err:
        return err
    tmp = f"/tmp/stat_{interfaz}_{int(time.time())}.pcap"
    _run(["tshark", "-i", interfaz, "-a", f"duration:{segundos}", "-w", tmp],
         timeout=segundos + 20, usar_sudo=True)
    if not os.path.exists(tmp) or os.path.getsize(tmp) == 0:
        return "Sin capturas. ¿Interfaz en monitor y con trafico?"
    salida = _run(["tshark", "-r", tmp, "-T", "fields", "-e", "wlan.fc.type_subtype"],
                  timeout=30, usar_sudo=True)
    try:
        os.unlink(tmp)
    except Exception:
        pass
    NOMBRES = {
        "0x0000":"Assoc-Req","0x0001":"Assoc-Resp","0x0002":"Reassoc-Req",
        "0x0003":"Reassoc-Resp","0x0004":"Probe-Req","0x0005":"Probe-Resp",
        "0x0008":"Beacon","0x000a":"Disassoc","0x000b":"Auth",
        "0x000c":"Deauth","0x000d":"Action","0x0018":"Block-ACK-Req",
        "0x0019":"Block-ACK","0x001b":"RTS","0x001c":"CTS","0x001d":"ACK",
        "0x0020":"Data","0x0024":"Null","0x0028":"QoS-Data","0x002c":"QoS-Null",
    }
    cont = Counter()
    for l in salida.split("\n"):
        l = l.strip()
        if l and not l.startswith(("[stderr]", "Timeout", "Error", "(sin")):
            cont[l.lower()] += 1
    total = sum(cont.values())
    if not total:
        return "No se capturaron frames 802.11."
    lines = [f"=== Estadisticas 802.11 ({segundos}s — {total} frames) ===",
             f"{'Tipo':<20} {'N':>6} {'%':>6}", "-"*36]
    for sub, n in cont.most_common():
        lines.append(f"{NOMBRES.get(sub, sub):<20} {n:>6} {100*n/total:>5.1f}%")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 7. Analisis de IEs HT/VHT/HE desde pcap (scapy, sin wlan_mgt.*)
# ---------------------------------------------------------------------------

# ── IDs de Information Elements 802.11 ──────────────────────────────────────
_IE_SSID             = 0
_IE_DS_PARAM         = 3
_IE_HT_CAPABILITIES  = 45
_IE_HT_OPERATION     = 61
_IE_VHT_CAPABILITIES = 191
_IE_VHT_OPERATION    = 192
_IE_EXTENSION        = 255   # Wi-Fi 6/6E usa IE extendido
_IE_EXT_HE_CAP       = 35   # sub-ID dentro de IE 255


def _bit(val, pos):
    return (val >> pos) & 1


def _bits(val, lo, hi):
    mask = (1 << (hi - lo + 1)) - 1
    return (val >> lo) & mask


def _decode_ht_capabilities(data: bytes) -> dict:
    if len(data) < 26:
        return {"error": f"IE demasiado corto ({len(data)} bytes, esperado >=26)"}
    ht_cap_info = struct.unpack_from("<H", data, 0)[0]
    mcs_set = data[3:19]
    rx_mcs_bitmask = mcs_set[0:10]
    nss = 0
    for i, byte_val in enumerate(rx_mcs_bitmask[:4]):
        if byte_val == 0xFF:
            nss = i + 1
    tx_info = mcs_set[12]
    tx_mcs_defined = _bit(tx_info, 0)
    tx_rx_mcs_not_equal = _bit(tx_info, 1)
    tx_max_nss = _bits(tx_info, 2, 3) + 1 if tx_mcs_defined and tx_rx_mcs_not_equal else nss
    return {
        "ldpc": bool(_bit(ht_cap_info, 0)),
        "channel_width_40mhz": bool(_bit(ht_cap_info, 1)),
        "sm_ps": ["static", "dynamic", "reserved", "disabled"][_bits(ht_cap_info, 2, 3)],
        "short_gi_20mhz": bool(_bit(ht_cap_info, 4)),
        "short_gi_40mhz": bool(_bit(ht_cap_info, 5)),
        "tx_stbc": bool(_bit(ht_cap_info, 6)),
        "rx_stbc_streams": _bits(ht_cap_info, 8, 9),
        "max_amsdu_7935": bool(_bit(ht_cap_info, 11)),
        "rx_mcs_set_hex": rx_mcs_bitmask.hex(),
        "rx_spatial_streams": nss,
        "tx_spatial_streams": tx_max_nss,
        "mcs_rx_highest_kbps": struct.unpack_from("<H", mcs_set, 10)[0] & 0x3FF,
    }


def _decode_ht_operation(data: bytes) -> dict:
    if len(data) < 22:
        return {"error": f"IE demasiado corto ({len(data)} bytes, esperado >=22)"}
    primary_ch = data[0]
    info1 = data[1]
    secondary_offset = _bits(info1, 0, 1)
    offsets = ["none/20MHz", "+1 (above)", "reserved", "-1 (below)"]
    return {
        "primary_channel": primary_ch,
        "secondary_channel_offset": offsets[secondary_offset],
        "sta_channel_width_40mhz": bool(_bit(info1, 2)),
        "ht_protection": _bits(data[2], 0, 1),
        "non_greenfield_present": bool(_bit(data[2], 2)),
        "obss_non_ht_present": bool(_bit(data[2], 4)),
    }


def _decode_vht_capabilities(data: bytes) -> dict:
    if len(data) < 12:
        return {"error": f"IE demasiado corto ({len(data)} bytes, esperado >=12)"}
    vht_cap = struct.unpack_from("<I", data, 0)[0]
    rx_mcs_map = struct.unpack_from("<H", data, 4)[0]
    rx_highest = struct.unpack_from("<H", data, 6)[0] & 0x1FFF
    tx_mcs_map = struct.unpack_from("<H", data, 8)[0]
    tx_highest = struct.unpack_from("<H", data, 10)[0] & 0x1FFF
    max_mpdu_sizes = [3895, 7991, 11454]
    supported_bw = ["80MHz only", "160MHz", "80+80MHz", "reserved"]

    def parse_mcs_map(val):
        mcs_labels = ["MCS 0-7", "MCS 0-8", "MCS 0-9", "not supported"]
        result = {}
        max_nss = 0
        for nss in range(1, 9):
            entry = (val >> ((nss - 1) * 2)) & 0x3
            if entry != 3:
                max_nss = nss
                result[f"NSS{nss}"] = mcs_labels[entry]
        result["max_spatial_streams"] = max_nss
        return result

    bw_idx = _bits(vht_cap, 0, 1)
    return {
        "max_mpdu_length": max_mpdu_sizes[bw_idx] if bw_idx < 3 else "reserved",
        "supported_channel_width": supported_bw[_bits(vht_cap, 2, 3)],
        "rx_ldpc": bool(_bit(vht_cap, 4)),
        "short_gi_80mhz": bool(_bit(vht_cap, 5)),
        "short_gi_160mhz": bool(_bit(vht_cap, 6)),
        "tx_stbc": bool(_bit(vht_cap, 7)),
        "rx_stbc": _bits(vht_cap, 8, 10),
        "su_beamformer": bool(_bit(vht_cap, 11)),
        "su_beamformee": bool(_bit(vht_cap, 12)),
        "mu_beamformer": bool(_bit(vht_cap, 19)),
        "mu_beamformee": bool(_bit(vht_cap, 20)),
        "rx_mcs_map": parse_mcs_map(rx_mcs_map),
        "rx_highest_data_rate_mbps": rx_highest or "not specified",
        "tx_mcs_map": parse_mcs_map(tx_mcs_map),
        "tx_highest_data_rate_mbps": tx_highest or "not specified",
    }


def _decode_vht_operation(data: bytes) -> dict:
    if len(data) < 5:
        return {"error": f"IE demasiado corto ({len(data)} bytes)"}
    widths = {0: "20/40MHz (HT)", 1: "80MHz", 2: "160MHz", 3: "80+80MHz"}
    return {
        "channel_width": widths.get(data[0], f"unknown({data[0]})"),
        "channel_center_0": data[1],
        "channel_center_1": data[2],
    }


def _decode_he_capabilities(data: bytes) -> dict:
    if len(data) < 22:
        return {"error": f"IE HE demasiado corto ({len(data)} bytes)"}
    mac_cap = int.from_bytes(data[0:6], "little")
    phy_cap = int.from_bytes(data[6:17], "little")
    mcs_nss = data[17:]
    ch_width_set = _bits(phy_cap, 1, 7)
    bw_le_80 = bool(_bit(ch_width_set, 0))
    bw_160   = bool(_bit(ch_width_set, 2))

    def he_mcs_label(val):
        return ["MCS 0-7", "MCS 0-9", "MCS 0-11", "not supported"][val & 0x3]

    mcs_map = {}
    if len(mcs_nss) >= 4:
        rx_map_80 = struct.unpack_from("<H", mcs_nss, 0)[0]
        tx_map_80 = struct.unpack_from("<H", mcs_nss, 2)[0]
        max_nss = 0
        for nss in range(1, 9):
            rx = (rx_map_80 >> ((nss - 1) * 2)) & 0x3
            if rx != 3:
                max_nss = nss
                mcs_map[f"NSS{nss}_rx"] = he_mcs_label(rx)
                tx = (tx_map_80 >> ((nss - 1) * 2)) & 0x3
                mcs_map[f"NSS{nss}_tx"] = he_mcs_label(tx)
        mcs_map["max_spatial_streams"] = max_nss

    return {
        "htc_he_support": bool(_bit(mac_cap, 1)),
        "twt_requester": bool(_bit(mac_cap, 2)),
        "twt_responder": bool(_bit(mac_cap, 3)),
        "bw_support_le_80mhz": bw_le_80,
        "bw_support_160mhz": bw_160,
        "su_beamformer": bool(_bit(phy_cap, 48)),
        "su_beamformee": bool(_bit(phy_cap, 49)),
        "mu_beamformer": bool(_bit(phy_cap, 50)),
        "mcs_nss_map_80mhz": mcs_map,
    }


def _parse_ies(payload: bytes) -> dict:
    """Recorre el payload de un beacon y extrae IEs por ID."""
    ies = {}
    i = 0
    while i + 1 < len(payload):
        ie_id = payload[i]
        ie_len = payload[i + 1]
        if i + 2 + ie_len > len(payload):
            break
        ie_data = payload[i + 2: i + 2 + ie_len]

        if ie_id == _IE_SSID:
            try:
                ies["ssid"] = ie_data.decode("utf-8", errors="replace")
            except Exception:
                ies["ssid"] = ie_data.hex()
        elif ie_id == _IE_DS_PARAM and ie_len >= 1:
            ies["ds_channel"] = ie_data[0]
        elif ie_id == _IE_HT_CAPABILITIES:
            ies["ht_capabilities"] = _decode_ht_capabilities(ie_data)
        elif ie_id == _IE_HT_OPERATION:
            ies["ht_operation"] = _decode_ht_operation(ie_data)
        elif ie_id == _IE_VHT_CAPABILITIES:
            ies["vht_capabilities"] = _decode_vht_capabilities(ie_data)
        elif ie_id == _IE_VHT_OPERATION:
            ies["vht_operation"] = _decode_vht_operation(ie_data)
        elif ie_id == _IE_EXTENSION and ie_len >= 1:
            if ie_data[0] == _IE_EXT_HE_CAP:
                ies["he_capabilities"] = _decode_he_capabilities(ie_data[1:])

        i += 2 + ie_len
    return ies


@mcp.tool()
def analizar_ies_pcap(nombre: str,
                      filtro_ssid: str = "",
                      filtro_bssid: str = "") -> str:
    """Extrae y decodifica IEs 802.11 HT/VHT/HE de beacons en un .pcap usando scapy.
    No depende de wlan_mgt.* ni de la version de tshark instalada.

    nombre       -- fichero pcap en el directorio de capturas (ej: 'beacons_multimedia.pcap').
                    Usa listar_pcaps() para ver los disponibles.
    filtro_ssid  -- filtrar por SSID (parcial, case-insensitive). Opcional.
    filtro_bssid -- filtrar por BSSID exacto ('AA:BB:CC:DD:EE:FF'). Opcional.

    Devuelve por cada AP unico: generacion Wi-Fi, NSS, MCS set, BW, beamforming,
    LDPC, Short GI, TWT (Wi-Fi 6) y canal.
    """
    try:
        from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt
    except ImportError:
        return (
            "ERROR: scapy no esta instalado en el entorno.\n"
            "Instalalo con:  pip install scapy\n"
            "(dentro del venv: /home/usuario/mcp_tshark/mcp_env/bin/pip install scapy)"
        )

    ruta, err = _ruta_pcap_segura(nombre)
    if err:
        return err
    if not os.path.exists(ruta):
        return f"No existe el fichero '{nombre}'. Usa listar_pcaps() para ver los disponibles."

    try:
        paquetes = rdpcap(ruta)
    except Exception as e:
        return f"ERROR al leer el pcap con scapy: {e}"

    # Recopilar un beacon por BSSID unico
    aps = {}
    for pkt in paquetes:
        if not (pkt.haslayer(Dot11Beacon) and pkt.haslayer(Dot11)):
            continue
        bssid = pkt[Dot11].addr3
        if not bssid:
            continue
        bssid = bssid.upper()

        if filtro_bssid and bssid != filtro_bssid.upper():
            continue

        ssid = ""
        try:
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:
                    ssid = elt.info.decode("utf-8", errors="replace")
                    break
                elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass

        if filtro_ssid and filtro_ssid.lower() not in ssid.lower():
            continue

        if bssid not in aps:
            aps[bssid] = {"ssid": ssid, "pkt": pkt}

    if not aps:
        msg = f"No se encontraron beacons en '{nombre}'"
        if filtro_ssid:
            msg += f" con SSID='{filtro_ssid}'"
        if filtro_bssid:
            msg += f" con BSSID='{filtro_bssid}'"
        return msg + ". Prueba sin filtros."

    lineas = [
        f"=== IEs HT/VHT/HE extraidos de '{nombre}' ===",
        f"    {len(aps)} AP(s) unicos encontrados\n",
    ]

    for bssid, info in sorted(aps.items()):
        pkt = info["pkt"]
        ssid = info["ssid"] or "<oculto>"
        lineas.append("-" * 60)
        lineas.append(f"BSSID : {bssid}")
        lineas.append(f"SSID  : {ssid}")

        try:
            elt_layer = pkt.getlayer(Dot11Elt)
            raw_ies = bytes(elt_layer)
        except Exception as e:
            lineas.append(f"  ERROR extrayendo IEs: {e}")
            continue

        ies = _parse_ies(raw_ies)

        ch_ds  = ies.get("ds_channel")
        ch_ht  = ies.get("ht_operation", {}).get("primary_channel")
        ch_vht = ies.get("vht_operation", {}).get("channel_center_0")
        lineas.append(f"Canal : DS={ch_ds}  HT_op={ch_ht}  VHT_center={ch_vht}")

        gen = "Wi-Fi 4 (802.11n)"
        if "he_capabilities" in ies:
            gen = "Wi-Fi 6 (802.11ax)"
        elif "vht_capabilities" in ies:
            gen = "Wi-Fi 5 (802.11ac)"
        lineas.append(f"Gen.  : {gen}")

        # HT Capabilities
        if "ht_capabilities" in ies:
            ht = ies["ht_capabilities"]
            lineas.append("\n  [HT Capabilities - IE 45]")
            if "error" in ht:
                lineas.append(f"    {ht['error']}")
            else:
                lineas.append(f"    Spatial streams Rx : {ht.get('rx_spatial_streams')}")
                lineas.append(f"    Spatial streams Tx : {ht.get('tx_spatial_streams')}")
                lineas.append(f"    40 MHz BW          : {ht.get('channel_width_40mhz')}")
                lineas.append(f"    Short GI 20 MHz    : {ht.get('short_gi_20mhz')}")
                lineas.append(f"    Short GI 40 MHz    : {ht.get('short_gi_40mhz')}")
                lineas.append(f"    LDPC               : {ht.get('ldpc')}")
                lineas.append(f"    Tx STBC            : {ht.get('tx_stbc')}")
                lineas.append(f"    Rx STBC streams    : {ht.get('rx_stbc_streams')}")
                lineas.append(f"    SM Power Save      : {ht.get('sm_ps')}")
                lineas.append(f"    Max AMSDU 7935B    : {ht.get('max_amsdu_7935')}")
                lineas.append(f"    MCS Rx bitmask     : {ht.get('rx_mcs_set_hex')}")
                lineas.append(f"    Max Rx rate (kbps) : {ht.get('mcs_rx_highest_kbps')}")
        else:
            lineas.append("\n  [HT Capabilities - IE 45] : no presente")

        # HT Operation
        if "ht_operation" in ies:
            ht_op = ies["ht_operation"]
            lineas.append("\n  [HT Operation - IE 61]")
            if "error" in ht_op:
                lineas.append(f"    {ht_op['error']}")
            else:
                lineas.append(f"    Canal primario     : {ht_op.get('primary_channel')}")
                lineas.append(f"    Canal secundario   : {ht_op.get('secondary_channel_offset')}")
                lineas.append(f"    STA BW 40 MHz      : {ht_op.get('sta_channel_width_40mhz')}")
                lineas.append(f"    HT protection      : {ht_op.get('ht_protection')}")

        # VHT Capabilities
        if "vht_capabilities" in ies:
            vht = ies["vht_capabilities"]
            lineas.append("\n  [VHT Capabilities - IE 191]")
            if "error" in vht:
                lineas.append(f"    {vht['error']}")
            else:
                rx_map = vht.get("rx_mcs_map", {})
                lineas.append(f"    Spatial streams    : {rx_map.get('max_spatial_streams')}")
                lineas.append(f"    BW soportado       : {vht.get('supported_channel_width')}")
                lineas.append(f"    Rx LDPC            : {vht.get('rx_ldpc')}")
                lineas.append(f"    Short GI 80 MHz    : {vht.get('short_gi_80mhz')}")
                lineas.append(f"    Short GI 160 MHz   : {vht.get('short_gi_160mhz')}")
                lineas.append(f"    SU Beamformer      : {vht.get('su_beamformer')}")
                lineas.append(f"    SU Beamformee      : {vht.get('su_beamformee')}")
                lineas.append(f"    MU Beamformer      : {vht.get('mu_beamformer')}")
                lineas.append(f"    MU Beamformee      : {vht.get('mu_beamformee')}")
                for k, v in rx_map.items():
                    if k.startswith("NSS"):
                        lineas.append(f"    Rx {k:<6}         : {v}")
                lineas.append(f"    Rx max rate (Mbps) : {vht.get('rx_highest_data_rate_mbps')}")
        else:
            lineas.append("\n  [VHT Capabilities - IE 191] : no presente")

        # VHT Operation
        if "vht_operation" in ies:
            vht_op = ies["vht_operation"]
            lineas.append("\n  [VHT Operation - IE 192]")
            if "error" in vht_op:
                lineas.append(f"    {vht_op['error']}")
            else:
                lineas.append(f"    Ancho de canal     : {vht_op.get('channel_width')}")
                lineas.append(f"    Centro seg. 0      : CH {vht_op.get('channel_center_0')}")
                lineas.append(f"    Centro seg. 1      : CH {vht_op.get('channel_center_1')}")

        # HE Capabilities (Wi-Fi 6)
        if "he_capabilities" in ies:
            he = ies["he_capabilities"]
            lineas.append("\n  [HE Capabilities - IE 255 ext 35]")
            if "error" in he:
                lineas.append(f"    {he['error']}")
            else:
                mcs_map = he.get("mcs_nss_map_80mhz", {})
                lineas.append(f"    Spatial streams    : {mcs_map.get('max_spatial_streams')}")
                lineas.append(f"    BW <=80 MHz        : {he.get('bw_support_le_80mhz')}")
                lineas.append(f"    BW 160 MHz         : {he.get('bw_support_160mhz')}")
                lineas.append(f"    SU Beamformer      : {he.get('su_beamformer')}")
                lineas.append(f"    SU Beamformee      : {he.get('su_beamformee')}")
                lineas.append(f"    MU Beamformer      : {he.get('mu_beamformer')}")
                lineas.append(f"    TWT responder      : {he.get('twt_responder')}")
                lineas.append(f"    HTC-HE support     : {he.get('htc_he_support')}")
                for k, v in mcs_map.items():
                    if k.startswith("NSS"):
                        lineas.append(f"    {k:<20}: {v}")
        else:
            lineas.append("\n  [HE Capabilities - IE 255/35] : no presente (no es Wi-Fi 6)")

        lineas.append("")

    return "\n".join(lineas)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
