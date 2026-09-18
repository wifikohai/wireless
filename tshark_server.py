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

# Directorio de configuracion propio de Wireshark usado solo para el descifrado WPA.
# Contiene el fichero '80211_keys' en formato UAT de Wireshark, una clave por linea:
#     "wpa-pwd","MiPassphrase:MI_SSID"
#     "wpa-psk","<64 caracteres hex>"
# Se le pasa a tshark via WIRESHARK_CONFIG_DIR en vez de con -o uat:80211_keys:...
# porque la linea de comandos es visible para cualquier usuario del host ('ps') y la
# passphrase no debe aparecer ahi. El fichero se crea a mano en el host, con chmod 600.
WPA_PROFILE_DIR = os.path.expanduser("~/mcp_tshark/wireshark_profile")
WPA_KEYS_FILE = os.path.join(WPA_PROFILE_DIR, "80211_keys")
os.makedirs(WPA_PROFILE_DIR, exist_ok=True)
os.chmod(WPA_PROFILE_DIR, 0o700)

INTERFACES_PERMITIDAS = []  # p.ej. ["wlan0", "wlan0mon"]
NOMBRE_VALIDO = re.compile(r"^[a-zA-Z0-9_.-]{1,20}$")
# Nombre de fichero pcap seguro: solo letras, numeros, _ - . y termina en .pcap/.pcapng
PCAP_VALIDO = re.compile(r"^[a-zA-Z0-9_.-]{1,80}\.(pcap|pcapng)$")
MAC_VALIDA = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


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


def _validar_mac(mac: str) -> str | None:
    if not MAC_VALIDA.match(mac):
        return f"MAC no valida: '{mac}'. Formato esperado 'aa:bb:cc:dd:ee:ff'."
    return None


def _cmd_tshark(descifrar: bool = False) -> tuple[list, str]:
    """Construye el comando base de tshark, activando el descifrado WPA si se pide.

    Devuelve (comando_base, aviso). 'aviso' es texto a anteponer a la salida, "" si
    no hay nada que avisar; si se pide descifrar y no hay claves configuradas se
    devuelve el comando SIN descifrado mas el aviso correspondiente (no se falla:
    el analisis 802.11 en claro sigue siendo util).
    """
    if not descifrar:
        return ["tshark"], ""
    if not os.path.isfile(WPA_KEYS_FILE):
        return ["tshark"], (f"[!] Se pidio descifrar pero no existe {WPA_KEYS_FILE}: "
                            f"se continua SIN descifrar. Ver estado_descifrado_wpa().\n\n")
    return (["env", f"WIRESHARK_CONFIG_DIR={WPA_PROFILE_DIR}", "tshark",
             "-o", "wlan.enable_decryption:TRUE"], "")


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
        salida = f"=== airmon-ng start {interfaz} ===\n"
        salida += _run(["airmon-ng", "start", interfaz], timeout=20, usar_sudo=True)
        # Con airmon-ng moderno (no destructivo) la interfaz base puede quedar
        # como VIF managed residual en el mismo phy que la nueva *mon; si se deja
        # 'up' bloquea fijar_canal en la interfaz monitor con "Device or resource
        # busy". Bajarla es seguro aunque no exista (falla en stderr, no fatal).
        iface_base = interfaz.replace("mon", "")
        salida += f"\n\n=== Bajar {iface_base} (VIF managed residual) ===\n"
        salida += _run(["ip", "link", "set", iface_base, "down"], usar_sudo=True)
        time.sleep(5)
        salida += "\n\n=== Reiniciar NetworkManager ===\n"
        salida += _run(["systemctl", "restart", "NetworkManager"], timeout=20, usar_sudo=True)
        time.sleep(8)
        return salida
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
    canal: numero de canal (2.4GHz:1-13; 5GHz:36..165).
    ancho: 'HT20'(20MHz), 'HT40+'/'HT40-'(40MHz), '80MHz', '160MHz', '5MHz', '10MHz'.

    No soporta 6 GHz: se usa 'iw set channel', que no puede desambiguar un numero
    de canal de 6 GHz (haria falta 'iw set freq <MHz>'). Da igual en la practica,
    porque ningun radio de este host opera en 6 GHz (wlan0/wlan1 son 2.4 + 5 GHz).
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
# 3bis. Diccionarios de interpretacion 802.11 (reason/status codes)
# ---------------------------------------------------------------------------

_REASON_CODES = {
    1: "No especificado", 2: "Autenticacion previa ya no valida",
    3: "Deauth: STA abandona IBSS/ESS", 4: "Disassoc por inactividad",
    5: "Disassoc: AP no puede gestionar mas STAs", 6: "Frame clase 2 de STA no autenticada",
    7: "Frame clase 3 de STA no asociada", 8: "Disassoc: STA abandona el BSS",
    9: "STA solicitando (re)asociacion no autenticada",
    10: "Capacidades de potencia inaceptables", 11: "Canales soportados inaceptables",
    12: "Disassoc por BSS Transition Management",
    13: "Elemento invalido (IE mal formado)", 14: "Fallo de MIC (Message Integrity Code)",
    15: "Timeout del 4-Way Handshake", 16: "Timeout del Group Key Handshake",
    17: "Elemento distinto entre 4-Way Handshake y (Re)Assoc/Probe/Beacon",
    18: "Cipher de grupo invalido", 19: "Cipher pairwise invalido",
    20: "AKMP invalido", 21: "Version de RSNE no soportada",
    22: "Capacidades RSNE invalidas", 23: "Fallo de autenticacion 802.1X",
    24: "Cipher rechazado por politica de seguridad",
    30: "Disassoc por falta de QoS", 31: "Disassoc por exceso de tramas sin ACK",
    32: "Disassoc por condiciones de canal pobres", 33: "STA transmitiendo fuera de su TXOP",
    34: "Exceso de perdida de tramas (peer)", 36: "Motivo QoS no especificado (peer)",
    37: "No autorizado / requisitos regulatorios",
    38: "AP sin canales disponibles", 39: "Disassoc por deteccion de radar",
    40: "AP no soporta el cipher solicitado", 45: "Peer no soporta el cipher solicitado",
    46: "Violacion de politica PMF (deauth protegido)",
    47: "Frame de auth con numero de secuencia fuera de lo esperado",
}

_STATUS_CODES = {
    0: "Exito", 1: "Fallo no especificado",
    10: "No soporta todas las capacidades solicitadas",
    11: "Reasociacion denegada: no se puede confirmar asociacion existente",
    12: "Asociacion denegada (motivo fuera del estandar)",
    13: "Algoritmo de autenticacion no soportado",
    14: "Numero de secuencia de auth fuera de lo esperado",
    15: "Auth rechazada: fallo de challenge",
    16: "Auth rechazada: timeout esperando siguiente frame",
    17: "AP no puede gestionar mas STAs asociadas",
    18: "STA no soporta las tasas de datos requeridas (BSSBasicRateSet)",
    19: "STA no soporta preambulo corto",
    20: "STA no soporta gestion de espectro",
    21: "STA no cumple requisitos de capacidad de potencia",
    22: "STA no soporta los canales requeridos",
    23: "STA no soporta Short Slot Time",
    24: "STA no soporta DSSS-OFDM",
    25: "Listen interval demasiado grande",
    26: "Solicitud rechazada temporalmente, reintentar",
    39: "STA no soporta HT",
    40: "Violacion de politica PMF (Robust Management Frame)",
    41: "Fallo no especificado relacionado con QoS",
    43: "Asociacion denegada por condiciones de canal pobres",
    50: "STA no soporta VHT",
    94: "Se requiere Anti-Clogging Token",
}


def _parse_int_field(s: str) -> int | None:
    s = s.strip()
    if not s:
        return None
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def _describir_reason(valor: str) -> str:
    codigo = _parse_int_field(valor)
    if codigo is None:
        return valor
    return f"{codigo} ({_REASON_CODES.get(codigo, 'ver estandar 802.11')})"


def _describir_status(valor: str) -> str:
    codigo = _parse_int_field(valor)
    if codigo is None:
        return valor
    return f"{codigo} ({_STATUS_CODES.get(codigo, 'ver estandar 802.11')})"


def _codigos_en_columna(salida: str, num_campos: int, idx_codigo: int) -> set:
    """Extrae los codigos numericos de una columna de salida '-E separator=|', antes
    de traducirlos a texto. Trabajar con el numero y no con su traduccion evita que
    la logica de veredicto dependa de como este redactado _REASON_CODES."""
    codigos = set()
    for l in salida.split("\n"):
        partes = l.split("|")
        if len(partes) != num_campos:
            continue
        valor = _parse_int_field(partes[idx_codigo])
        if valor is not None:
            codigos.add(valor)
    return codigos


def _traducir_columna(salida: str, num_campos: int, idx_codigo: int, traductor) -> str:
    """Sustituye, linea a linea, la columna idx_codigo de una salida '-E separator=|'
    por el resultado de traductor(valor). Deja intactas las lineas que no encajan
    (errores, cabeceras, lineas con menos/mas campos)."""
    lineas_out = []
    for l in salida.split("\n"):
        partes = l.split("|")
        if len(partes) == num_campos and partes[idx_codigo].strip():
            partes[idx_codigo] = traductor(partes[idx_codigo])
            lineas_out.append("|".join(partes))
        else:
            lineas_out.append(l)
    return "\n".join(lineas_out)


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
    """Captura frames de ASOCIACION y reasociacion, con el status_code traducido a texto."""
    df = ("wlan.fc.type_subtype==0x00 or wlan.fc.type_subtype==0x01 or "
          "wlan.fc.type_subtype==0x02 or wlan.fc.type_subtype==0x03")
    campos = ["frame.time_relative", "wlan.sa", "wlan.da", "wlan.bssid",
              "wlan.fc.type_subtype", "wlan.ssid", "wlan.fixed.status_code"]
    salida = _captura_wlan(interfaz, df, paquetes, campos)
    return _traducir_columna(salida, len(campos), len(campos) - 1, _describir_status)


def _capturar_autenticacion_interno(interfaz: str, paquetes: int) -> tuple[str, set]:
    """Captura auth/deauth/disassoc y devuelve (texto_traducido, reason_codes_vistos).

    Los codigos salen en crudo antes de traducirlos, para que diagnosticar_autenticacion
    razone sobre numeros del estandar en vez de sobre cadenas en castellano."""
    df = ("wlan.fc.type_subtype==0x0b or wlan.fc.type_subtype==0x0c or "
          "wlan.fc.type_subtype==0x0a")
    campos = ["frame.time_relative", "wlan.sa", "wlan.da", "wlan.bssid",
              "wlan.fc.type_subtype", "wlan.fixed.auth.alg", "wlan.fixed.reason_code"]
    salida = _captura_wlan(interfaz, df, paquetes, campos)
    codigos = _codigos_en_columna(salida, len(campos), len(campos) - 1)
    texto = _traducir_columna(salida, len(campos), len(campos) - 1, _describir_reason)
    return texto, codigos


@mcp.tool()
def capturar_autenticacion(interfaz: str, paquetes: int = 20) -> str:
    """Captura frames de AUTENTICACION y desautenticacion (auth, deauth, disassoc),
    con el reason_code traducido a texto."""
    texto, _ = _capturar_autenticacion_interno(interfaz, paquetes)
    return texto


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


_EAPOL_KEY_INFO_KEYTYPE = 0x0008  # 1 = pairwise (M1-M4), 0 = group (G1-G2)
_EAPOL_KEY_INFO_INSTALL = 0x0040
_EAPOL_KEY_INFO_ACK     = 0x0080
_EAPOL_KEY_INFO_MIC     = 0x0100
_EAPOL_KEY_INFO_SECURE  = 0x0200

_EAPOL_MSGNR_DESC = {
    1: "M1 (AP->STA, ANonce)",
    2: "M2 (STA->AP, SNonce+MIC)",
    3: "M3 (AP->STA, GTK+MIC, Install)",
    4: "M4 (STA->AP, Confirm)",
}


def _clasificar_eapol_msg(key_info: int) -> str:
    """Clasifica un frame EAPOL-Key en M1-M4 (pairwise) o G1-G2 (group) a partir
    de los bits ACK/MIC/Secure/KeyType del key_info, sin depender de
    eapol.keydes.msgnr (no disponible en todas las versiones de tshark)."""
    pairwise = bool(key_info & _EAPOL_KEY_INFO_KEYTYPE)
    ack = bool(key_info & _EAPOL_KEY_INFO_ACK)
    mic = bool(key_info & _EAPOL_KEY_INFO_MIC)
    secure = bool(key_info & _EAPOL_KEY_INFO_SECURE)

    if pairwise:
        if ack and not mic and not secure:
            return "M1 (AP->STA, ANonce)"
        if not ack and mic and not secure:
            return "M2 (STA->AP, SNonce+MIC)"
        if ack and mic and secure:
            return "M3 (AP->STA, GTK+MIC, Install)"
        if not ack and mic and secure:
            return "M4 (STA->AP, Confirm)"
        return "pairwise (patron key_info no reconocido)"
    else:
        if ack and mic:
            return "G1 (AP->STA, Group Key)"
        if not ack and mic:
            return "G2 (STA->AP, Group Key ACK)"
        return "group (patron key_info no reconocido)"


def _analizar_eapol_capturado(salida: str) -> tuple[str, dict]:
    """Post-procesa la salida de capturar_eapol: clasifica cada frame en M1-M4/G1-G2,
    agrupa por par STA<->AP y detecta retransmisiones o handshakes incompletos.

    Usa wlan_rsna_eapol.keydes.msgnr (numero de mensaje ya calculado por tshark)
    cuando esta presente; si no (p.ej. mensajes de Group Key, que msgnr no cubre),
    cae al decodificador de bits de key_info.

    Devuelve (texto_para_el_usuario, hechos). Los `hechos` son el dato que consume
    el veredicto de diagnosticar_autenticacion: antes lo deducia buscando subcadenas
    dentro de este mismo texto, asi que reescribir un literal rompia el diagnostico
    en silencio."""
    eventos = []
    for l in salida.split("\n"):
        partes = l.split("|")
        if len(partes) != 5:
            continue
        t_str, sa, da, msgnr_str, key_info_str = partes
        try:
            t = float(t_str)
        except ValueError:
            continue
        msgnr = _parse_int_field(msgnr_str)
        ki = _parse_int_field(key_info_str)
        if msgnr in _EAPOL_MSGNR_DESC:
            msg = _EAPOL_MSGNR_DESC[msgnr]
        elif ki is not None:
            msg = _clasificar_eapol_msg(ki)
        else:
            continue
        eventos.append({"t": t, "sa": sa, "da": da, "msg": msg})

    hechos = {
        "eventos_eapol": len(eventos),
        "pares": 0,
        "handshake_incompleto": False,
        "handshake_completo": False,
        "m1_retransmitido": False,
        "m3_retransmitido": False,
    }
    if not eventos:
        return salida, hechos

    pares: dict[tuple, list] = {}
    for e in eventos:
        clave = tuple(sorted([e["sa"], e["da"]]))
        pares.setdefault(clave, []).append(e)
    hechos["pares"] = len(pares)

    resumen = ["", "=== Analisis 4-Way Handshake (M1-M4 / G1-G2) ==="]
    for clave, evs in pares.items():
        evs.sort(key=lambda e: e["t"])
        secuencia = " -> ".join(e["msg"].split(" ")[0] for e in evs)
        resumen.append(f"\nPar {clave[0]} <-> {clave[1]}:")
        resumen.append(f"  Secuencia: {secuencia}")

        m1_count = sum(1 for e in evs if e["msg"].startswith("M1"))
        m3_count = sum(1 for e in evs if e["msg"].startswith("M3"))
        tiene_m1 = m1_count > 0
        tiene_m4 = any(e["msg"].startswith("M4") for e in evs)

        if m1_count > 1:
            hechos["m1_retransmitido"] = True
            resumen.append(f"  [!] M1 visto {m1_count} veces -> posible retransmision/timeout "
                            f"(AP reenviando ANonce, esperando M2 del cliente)")
        if m3_count > 1:
            hechos["m3_retransmitido"] = True
            resumen.append(f"  [!] M3 visto {m3_count} veces -> posible retransmision/timeout "
                            f"(AP reenviando GTK, esperando M4 del cliente)")
        if tiene_m1 and not tiene_m4:
            hechos["handshake_incompleto"] = True
            resumen.append("  [!] Handshake incompleto en esta captura: no se vio M4 "
                            "(no termino en la ventana capturada, o fallo)")
        elif tiene_m4:
            hechos["handshake_completo"] = True
            resumen.append("  [OK] Handshake completo (se vieron M1..M4)")

    return salida + "\n" + "\n".join(resumen), hechos


def _capturar_eapol_interno(interfaz: str, paquetes: int) -> tuple[str, dict]:
    """Captura EAPOL y devuelve (texto, hechos). Lo usan tanto capturar_eapol como
    diagnosticar_autenticacion, que necesita los hechos y no solo el texto."""
    # Wireshark/tshark disecciona el key descriptor RSNA bajo wlan_rsna_eapol.*
    # (no eapol.keydes.* como en versiones/dissectors mas antiguos).
    campos = ["frame.time_relative", "wlan.sa", "wlan.da",
              "wlan_rsna_eapol.keydes.msgnr", "wlan_rsna_eapol.keydes.key_info"]
    salida = _captura_wlan(interfaz, "eapol", paquetes, campos)
    return _analizar_eapol_capturado(salida)


@mcp.tool()
def capturar_eapol(interfaz: str, paquetes: int = 20) -> str:
    """Captura frames EAPOL (handshake WPA/WPA2/WPA3 4-way), clasifica cada mensaje
    en M1-M4/G1-G2 y detecta retransmisiones o handshakes incompletos por par STA-AP."""
    texto, _ = _capturar_eapol_interno(interfaz, paquetes)
    return texto


@mcp.tool()
def diagnosticar_autenticacion(interfaz: str, paquetes: int = 30) -> str:
    """Diagnostico combinado de fallos de autenticacion (protocolo, no credenciales):
    captura auth/deauth/disassoc (reason_code traducido) y EAPOL (clasificado M1-M4,
    con deteccion de retransmision/timeout) en la misma pasada, y da un veredicto.

    interfaz: interfaz en modo monitor (ej: 'wlan1mon').
    paquetes: paquetes a esperar en cada una de las dos capturas (auth y EAPOL).
    """
    auth, codigos = _capturar_autenticacion_interno(interfaz, paquetes)
    eapol, hechos = _capturar_eapol_interno(interfaz, paquetes)

    # Reason codes del estandar 802.11 en los que se apoya el veredicto.
    RC_TIMEOUT_4WAY      = 15
    RC_TIMEOUT_GROUP_KEY = 16
    RC_FALLO_8021X       = 23

    veredicto = []
    if RC_TIMEOUT_4WAY in codigos or hechos["handshake_incompleto"]:
        veredicto.append("Posible fallo en el 4-Way Handshake (timeout/retransmision) "
                          "-> revisar PSK/AKM/PMF configurados en el cliente.")
    if RC_FALLO_8021X in codigos:
        veredicto.append("Fallo de autenticacion 802.1X -> revisar RADIUS/EAP en el lado servidor.")
    if RC_TIMEOUT_GROUP_KEY in codigos:
        veredicto.append("Timeout del Group Key Handshake -> posible perdida de conectividad "
                          "justo despues del 4-way.")
    if not veredicto:
        veredicto.append("Sin patrones de fallo reconocidos en esta captura; revisar manualmente "
                          "las secciones de auth y EAPOL de abajo.")

    return (f"=== AUTENTICACION / DEAUTH / DISASSOC ===\n{auth}\n\n"
            f"=== EAPOL (4-Way Handshake) ===\n{eapol}\n\n"
            f"=== VEREDICTO ===\n" + "\n".join(f"- {v}" for v in veredicto))


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

    # tshark escribe el pcap como root (usar_sudo=True) con permisos que dependen del
    # umask del proceso systemd, a veces 600 -> ilegible para tools que no usan sudo
    # (analizar_ies_pcap, via scapy). Se deja en 644 para que cualquier tool posterior
    # pueda leerlo, con o sin sudo.
    _run(["chmod", "644", ruta], timeout=10, usar_sudo=True)

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
def leer_pcap(nombre: str, modo: str = "resumen", filtro: str = "", max_lineas: int = 100,
              descifrar: bool = False) -> str:
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
    descifrar: si True, descifra el trafico WPA/WPA2 con las claves configuradas en el
            host (ver estado_descifrado_wpa) y los data frames pasan a verse como
            DHCP/ARP/DNS/IP en vez de 'QoS Data' cifrado. Requiere que el PCAP contenga
            el 4-Way Handshake del cliente: sin M1-M4 no se puede derivar la PTK y el
            unicast sigue cifrado (el multicast necesita ademas la GTK, que va en M3).
    """
    ruta, err = _ruta_pcap_segura(nombre)
    if err:
        return err
    if not os.path.exists(ruta):
        return f"No existe el fichero '{nombre}'. Usa listar_pcaps() para ver los disponibles."

    base, aviso = _cmd_tshark(descifrar)

    if modo == "resumen":
        comando = base + ["-r", ruta]
        if filtro:
            comando += ["-Y", filtro]
    elif modo == "protocolos":
        comando = base + ["-r", ruta, "-q", "-z", "io,phs"]
    elif modo == "wlan":
        comando = base + ["-r", ruta, "-q", "-z", "wlan,stat"]
    elif modo == "conversaciones":
        comando = base + ["-r", ruta, "-q", "-z", "conv,wlan"]
    elif modo == "campos":
        comando = base + ["-r", ruta]
        if filtro:
            comando += ["-Y", filtro]
        comando += ["-T", "fields",
                    "-e", "frame.time_relative", "-e", "wlan.sa", "-e", "wlan.da",
                    "-e", "wlan.bssid", "-e", "wlan.fc.type_subtype", "-e", "wlan.ssid",
                    "-E", "separator=|"]
    elif modo == "crudo":
        comando = base + ["-r", ruta]
        if filtro:
            comando += ["-Y", filtro]
    else:
        return ("Modo no valido. Usa: 'resumen', 'protocolos', 'wlan', "
                "'conversaciones', 'campos' o 'crudo'.")

    salida = aviso + _run(comando, timeout=60, usar_sudo=True)

    # Limita numero de lineas para no saturar la respuesta
    lineas = salida.split("\n")
    if len(lineas) > max_lineas:
        salida = "\n".join(lineas[:max_lineas])
        salida += f"\n\n... [salida truncada a {max_lineas} lineas de {len(lineas)} totales. "
        salida += "Usa un 'filtro' mas especifico o aumenta max_lineas.]"
    return salida


# ---------------------------------------------------------------------------
# 5b. Descifrado WPA y conectividad post-asociacion del cliente
# ---------------------------------------------------------------------------

_DHCP_MSG = {1: "DISCOVER (cliente pide IP)", 2: "OFFER (servidor ofrece)",
             3: "REQUEST (cliente acepta)", 4: "DECLINE (cliente rechaza)",
             5: "ACK (servidor confirma)", 6: "NAK (servidor deniega)",
             7: "RELEASE (cliente libera)", 8: "INFORM (cliente pide parametros)"}

_ARP_OP = {1: "request", 2: "reply", 3: "RARP request", 4: "RARP reply"}

_DNS_RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
              4: "NOTIMP", 5: "REFUSED"}


def _describir_dhcp(valor: str) -> str:
    codigo = _parse_int_field(valor)
    if codigo is None:
        return valor
    return f"{codigo} ({_DHCP_MSG.get(codigo, 'tipo DHCP desconocido')})"


def _describir_arp(valor: str) -> str:
    codigo = _parse_int_field(valor)
    if codigo is None:
        return valor
    return f"{codigo} ({_ARP_OP.get(codigo, 'opcode desconocido')})"


@mcp.tool()
def estado_descifrado_wpa() -> str:
    """Muestra si el descifrado WPA esta configurado: fichero de claves, permisos y que
    claves hay (tipo y SSID; el material de clave se muestra siempre enmascarado).

    Las claves NO se anaden desde aqui a proposito: pasarlas como parametro de una tool
    las dejaria escritas en la conversacion y en los logs del cliente MCP. Se crean a
    mano en el host y esta tool solo sirve para verificar que estan bien puestas.
    """
    salida = [f"Fichero de claves: {WPA_KEYS_FILE}"]

    if not os.path.isfile(WPA_KEYS_FILE):
        salida.append("Estado: NO EXISTE -> el descifrado esta desactivado.")
        salida.append("")
        salida.append("Para activarlo, en el host (una sola vez por red):")
        salida.append(f"  umask 077 && printf '%s\\n' "
                      f"'\"wpa-pwd\",\"MI_PASSPHRASE:MI_SSID\"' > {WPA_KEYS_FILE}")
        salida.append("")
        salida.append("Formato UAT de Wireshark, una clave por linea. Tipos admitidos:")
        salida.append('  "wpa-pwd","passphrase:SSID"  passphrase en claro. El SSID es opcional')
        salida.append("                               (si falta se usa el de la captura), pero")
        salida.append("                               conviene ponerlo si hay varias redes.")
        salida.append('  "wpa-psk","<64 hex>"         PMK ya derivada.')
        salida.append('  "wep","<hex>"                WEP (obsoleto).')
        return "\n".join(salida)

    modo = oct(os.stat(WPA_KEYS_FILE).st_mode & 0o777)
    salida.append(f"Estado: existe | permisos: {modo}")
    if modo != "0o600":
        salida.append(f"  [!] Permisos {modo}: deberian ser 600 -> chmod 600 {WPA_KEYS_FILE}")

    # Formato UAT: "<tipo>","<valor>" por linea.
    patron = re.compile(r'^\s*"([^"]*)"\s*,\s*"(.*)"\s*$')
    entradas, malas = [], []
    try:
        with open(WPA_KEYS_FILE, "r") as fh:
            for n, linea in enumerate(fh, 1):
                if not linea.strip() or linea.lstrip().startswith("#"):
                    continue
                m = patron.match(linea.rstrip("\n"))
                if m:
                    entradas.append((m.group(1), m.group(2)))
                else:
                    malas.append(n)
    except OSError as e:
        return "\n".join(salida) + f"\nNo se pudo leer el fichero: {e}"

    salida.append(f"Claves cargadas: {len(entradas)}")
    for tipo, valor in entradas:
        if tipo == "wpa-pwd" and ":" in valor:
            # Wireshark separa por el ULTIMO ':' (el SSID va al final).
            passph, ssid = valor.rsplit(":", 1)
            detalle = f"SSID '{ssid}' | passphrase oculta ({len(passph)} caracteres)"
        elif tipo == "wpa-pwd":
            detalle = (f"sin SSID (se usara el de la captura) | "
                       f"passphrase oculta ({len(valor)} caracteres)")
        else:
            detalle = f"material de clave oculto ({len(valor)} caracteres)"
        salida.append(f"  - {tipo}: {detalle}")
    if malas:
        salida.append(f"  [!] Lineas con formato invalido, tshark las rechazara: {malas}")

    salida.append("")
    salida.append("Uso: leer_pcap(nombre, descifrar=True) o "
                  "diagnosticar_conectividad_cliente(nombre, mac).")
    salida.append("Recuerda: el PCAP debe contener el 4-Way Handshake (M1-M4) del cliente; "
                  "sin el no se deriva la PTK y el unicast sigue cifrado.")
    return "\n".join(salida)


@mcp.tool()
def diagnosticar_conectividad_cliente(nombre: str, cliente_mac: str = "",
                                      max_lineas: int = 40) -> str:
    """Diagnostica el caso "asocia pero no navega" sobre un PCAP: descifra el trafico WPA
    y revisa DHCP, ARP y DNS del cliente para localizar donde se corta la cadena.

    Complementa a diagnosticar_autenticacion(): aquella cubre el fallo ANTES de la
    asociacion (auth/EAPOL), esta cubre lo que pasa DESPUES, cuando el cliente ya esta
    asociado pero no tiene servicio.

    Requiere claves configuradas (estado_descifrado_wpa) y un PCAP que contenga el
    4-Way Handshake del cliente. Flujo tipico:
      activar_modo_monitor -> fijar_canal -> capturar_a_pcap cubriendo la reconexion
      del cliente -> diagnosticar_conectividad_cliente(fichero, mac_cliente)

    nombre: fichero pcap (ver listar_pcaps()).
    cliente_mac: MAC del cliente (aa:bb:cc:dd:ee:ff). Vacio = todo el trafico del PCAP.
    max_lineas: limite de filas por seccion.
    """
    ruta, err = _ruta_pcap_segura(nombre)
    if err:
        return err
    if not os.path.exists(ruta):
        return f"No existe el fichero '{nombre}'. Usa listar_pcaps() para ver los disponibles."
    if cliente_mac:
        err = _validar_mac(cliente_mac)
        if err:
            return err

    base, aviso = _cmd_tshark(descifrar=True)
    if aviso:
        return (aviso + "Esta tool solo tiene sentido con descifrado: sin claves no se ve "
                "nada por encima de 802.11. Configura las claves y vuelve a intentarlo; "
                "mientras tanto, leer_pcap() sigue sirviendo para el analisis 802.11.")

    f_cli = f" && wlan.addr=={cliente_mac}" if cliente_mac else ""

    def _cuenta(df: str) -> int:
        salida = _run(base + ["-r", ruta, "-Y", df, "-T", "fields", "-e", "frame.number"],
                      timeout=60, usar_sudo=True)
        return sum(1 for l in salida.split("\n") if l.strip().isdigit())

    def _tabla(df: str, campos: list) -> str:
        comando = base + ["-r", ruta, "-Y", df, "-T", "fields"]
        for c in campos:
            comando += ["-e", c]
        comando += ["-E", "separator=|"]
        salida = _run(comando, timeout=60, usar_sudo=True)
        lineas = [l for l in salida.split("\n")
                  if l.strip() and l.strip() != "(sin salida)" and not l.startswith("[stderr]")]
        if not lineas:
            return "(ninguno)"
        if len(lineas) > max_lineas:
            return ("\n".join(lineas[:max_lineas]) +
                    f"\n... [truncado a {max_lineas} de {len(lineas)} filas]")
        return "\n".join(lineas)

    # --- 1. Comprobar que el descifrado ha funcionado de verdad -----------------
    n_eapol = _cuenta("eapol" + f_cli)
    n_prot = _cuenta("wlan.fc.type==2 && wlan.fc.protected==1" + f_cli)
    n_desc = _cuenta("wlan.fc.protected==1 && (ip || ipv6 || arp)" + f_cli)

    estado = [f"Frames EAPOL vistos: {n_eapol}",
              f"Data frames cifrados: {n_prot}",
              f"De ellos, descifrados con exito: {n_desc}"]

    if n_prot == 0:
        estado.append("[!] No hay data frames cifrados en esta captura (o para esta MAC): "
                      "el cliente no llego a intercambiar trafico, o se capturo en otro canal.")
    elif n_desc == 0:
        estado.append("[!] Descifrado SIN efecto. Causas por orden de probabilidad:")
        if n_eapol == 0:
            estado.append("    1. No hay 4-Way Handshake en la captura -> tshark no puede "
                          "derivar la PTK. Recaptura cubriendo la reconexion del cliente.")
        else:
            estado.append("    1. Handshake presente pero incompleto (faltan M1-M4 seguidos) "
                          "-> revisa con capturar_eapol/leer_pcap -Y eapol.")
        estado.append("    2. Passphrase o SSID incorrectos -> estado_descifrado_wpa().")
        estado.append("    3. La red usa WPA3-SAE o 802.1X: la passphrase no aplica "
                      "(WPA3-SAE no es descifrable con PSK).")
        return ("=== ESTADO DEL DESCIFRADO ===\n" + "\n".join(estado) +
                "\n\nSin descifrado efectivo no hay DHCP/ARP/DNS que analizar.")

    # --- 2. DHCP, ARP, DNS ------------------------------------------------------
    dhcp = _tabla("dhcp" + f_cli,
                  ["frame.time_relative", "wlan.sa", "dhcp.option.dhcp", "dhcp.ip.your"])
    dhcp = _traducir_columna(dhcp, 4, 2, _describir_dhcp)

    arp = _tabla("arp" + f_cli,
                 ["frame.time_relative", "arp.opcode", "arp.src.proto_ipv4",
                  "arp.dst.proto_ipv4"])
    arp = _traducir_columna(arp, 4, 1, _describir_arp)

    dns = _tabla("dns" + f_cli,
                 ["frame.time_relative", "dns.flags.response", "dns.qry.name",
                  "dns.flags.rcode"])

    # --- 3. Veredicto -----------------------------------------------------------
    n_disc = _cuenta("dhcp.option.dhcp==1" + f_cli)
    n_offer = _cuenta("dhcp.option.dhcp==2" + f_cli)
    n_req = _cuenta("dhcp.option.dhcp==3" + f_cli)
    n_ack = _cuenta("dhcp.option.dhcp==5" + f_cli)
    n_nak = _cuenta("dhcp.option.dhcp==6" + f_cli)
    n_arp_req = _cuenta("arp.opcode==1" + f_cli)
    n_arp_rep = _cuenta("arp.opcode==2" + f_cli)
    n_dns_q = _cuenta("dns.flags.response==0" + f_cli)
    n_dns_r = _cuenta("dns.flags.response==1" + f_cli)
    n_dns_fail = _cuenta("dns.flags.rcode>0" + f_cli)

    veredicto = []
    if n_disc and not n_offer:
        veredicto.append("DHCP: el cliente envia DISCOVER y nadie responde con OFFER -> "
                         "servidor DHCP caido, VLAN/SSID sin DHCP relay, o el AP no puentea "
                         "el broadcast al backbone.")
    elif n_nak:
        veredicto.append("DHCP: el servidor responde NAK -> el cliente pide una IP que ya no "
                         "le corresponde (cambio de subred tras roaming, o lease de otra VLAN).")
    elif n_req and not n_ack:
        veredicto.append("DHCP: hay REQUEST sin ACK -> pool agotado o el servidor descarta la "
                         "peticion. Revisa el scope DHCP.")
    elif n_ack:
        veredicto.append("DHCP: completado (se vio ACK). La IP se entrego correctamente.")
    elif not n_disc:
        veredicto.append("DHCP: sin trafico DHCP para este cliente -> IP estatica, lease aun "
                         "vigente de antes de la captura, o el cliente ni lo intento.")

    if n_arp_req and not n_arp_rep:
        veredicto.append("ARP: hay requests sin ninguna reply -> el cliente no resuelve su "
                         "gateway. Tipico de aislamiento de clientes en el AP, VLAN mal "
                         "asignada, o gateway inalcanzable a nivel L2.")
    elif n_arp_rep:
        veredicto.append("ARP: hay replies, la resolucion L2 funciona.")

    if n_dns_q and not n_dns_r:
        veredicto.append("DNS: consultas sin ninguna respuesta -> servidor DNS inalcanzable o "
                         "filtrado. Con IP y ARP correctos, este es el corte.")
    elif n_dns_fail:
        veredicto.append(f"DNS: {n_dns_fail} respuestas con rcode de error "
                         f"(SERVFAIL/NXDOMAIN/REFUSED) -> fallo de resolucion, no de WiFi.")
    elif n_dns_r:
        veredicto.append("DNS: resolucion correcta.")

    if not veredicto:
        veredicto.append("Sin patrones reconocidos. El descifrado funciona pero no hay "
                         "DHCP/ARP/DNS en la ventana capturada: amplia la duracion de "
                         "capturar_a_pcap o comprueba que el canal es el correcto.")

    ambito = f"cliente {cliente_mac}" if cliente_mac else "todos los clientes del PCAP"
    return (f"=== CONECTIVIDAD POST-ASOCIACION ({ambito}) ===\n"
            f"PCAP: {nombre}\n\n"
            f"--- Estado del descifrado ---\n" + "\n".join(estado) + "\n\n"
            f"--- DHCP (t | sa | tipo | ip ofrecida) ---\n{dhcp}\n\n"
            f"--- ARP (t | opcode | src ip | dst ip) ---\n{arp}\n\n"
            f"--- DNS (t | respuesta 0/1 | consulta | rcode) ---\n{dns}\n\n"
            f"=== VEREDICTO ===\n" + "\n".join(f"- {v}" for v in veredicto))


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


# ── scandump (WLAN Pi, BSD-3-Clause) ────────────────────────────────────────
# https://github.com/WLAN-Pi/scandump
# Escanea via la API netlink 802.11 y emite un PCAP con radiotap + beacons, en vez
# de texto que haya que parsear. Ventajas para este proyecto:
#   - no necesita modo monitor (va sobre la interfaz managed, p.ej. wlan0), asi que
#     no toca wlan1 ni pasa por activar_modo_monitor
#   - cubre todas las bandas de una pasada, no un solo canal
#   - la seguridad sale del IE RSN de verdad, no de buscar "RSN:" en una linea
# Se instala con CAP_NET_ADMIN, no con sudo completo.
_SCANDUMP_BIN = "/usr/local/bin/scandump"
_scandump_ok = None


def _scandump_disponible() -> bool:
    """Comprueba una vez por proceso si scandump esta instalado y es ejecutable."""
    global _scandump_ok
    if _scandump_ok is None:
        _scandump_ok = os.path.isfile(_SCANDUMP_BIN) and os.access(_SCANDUMP_BIN, os.X_OK)
    return _scandump_ok


def _ejecutar_scandump(interfaz: str, destino: str, frecuencias: str = "",
                       pasivo: bool = True, timeout: int = 60) -> str:
    """Lanza scandump dejando el PCAP en `destino`. Devuelve "" si todo fue bien,
    o un mensaje de error."""
    cmd = [_SCANDUMP_BIN, "-c", "1"]
    if pasivo:
        cmd.append("-p")
    if frecuencias:
        if not re.fullmatch(r"\d{4}(,\d{4})*", frecuencias.strip()):
            return "Lista de frecuencias no valida. Formato: '2437,5180,5200' (MHz)."
        cmd += ["-f", frecuencias.strip()]
    cmd += [interfaz, destino]
    salida = _run(cmd, timeout=timeout)
    if not os.path.exists(destino) or os.path.getsize(destino) == 0:
        return f"scandump no genero captura. Salida: {salida}"
    return ""


def _recolectar_scan_pcap(ruta: str) -> tuple[list, str]:
    """Extrae de un PCAP de scandump una lista de APs con senal y frecuencia
    (de radiotap) y los IEs ya decodificados."""
    try:
        from scapy.all import PcapReader, RadioTap, Dot11, Dot11Beacon, Dot11Elt
    except ImportError:
        return [], "scapy no esta instalado en el entorno del servidor."
    vistos, redes = set(), []
    try:
        with PcapReader(ruta) as lector:
            for pkt in lector:
                if not (pkt.haslayer(Dot11Beacon) and pkt.haslayer(Dot11)):
                    continue
                bssid = (pkt[Dot11].addr3 or "").lower()
                if not bssid or bssid in vistos:
                    continue
                try:
                    ies = _parse_ies(bytes(pkt.getlayer(Dot11Elt)))
                except Exception:
                    continue
                vistos.add(bssid)
                rt = pkt.getlayer(RadioTap) if pkt.haslayer(RadioTap) else None
                freq = getattr(rt, "ChannelFrequency", None) if rt else None
                redes.append({
                    "bssid": bssid,
                    "ssid": ies.get("ssid", "") or "",
                    "freq": str(freq) if freq else "",
                    "signal": str(getattr(rt, "dBm_AntSignal", "")) if rt else "",
                    "canal": str(ies.get("ds_channel") or _freq_a_canal(str(freq or ""))),
                    "seguridad": _resumen_seguridad(ies),
                })
    except Exception as e:
        return [], f"ERROR al leer el PCAP de scandump: {e}"
    return redes, ""


def _resumen_seguridad(ies: dict) -> str:
    """Resume la seguridad a partir del IE RSN decodificado de verdad, en vez de
    deducirla de que aparezca la cadena 'RSN:' en la salida de texto de iw."""
    rsn = ies.get("rsn")
    if not rsn or "error" in rsn:
        return "abierta/?"
    akms = rsn.get("akm_suites") or []
    etiquetas = []
    if any("SAE" in a for a in akms):
        etiquetas.append("WPA3")
    if any("PSK" in a for a in akms):
        etiquetas.append("WPA2")
    if any("802.1X" in a for a in akms):
        etiquetas.append("Enterprise")
    if any("OWE" in a for a in akms):
        etiquetas.append("OWE")
    if not etiquetas:
        etiquetas.append("RSN")
    if rsn.get("pmf_required"):
        etiquetas.append("PMF-req")
    elif rsn.get("pmf_capable"):
        etiquetas.append("PMF-opt")
    return "/".join(etiquetas)


@mcp.tool()
def escanear_a_pcap(interfaz: str = "wlan0", frecuencias: str = "",
                    pasivo: bool = True, nombre: str = "") -> str:
    """Escanea redes con scandump y guarda el resultado como PCAP (radiotap + beacons).

    A diferencia de capturar_a_pcap, NO necesita modo monitor: va sobre la interfaz
    managed y barre todas las bandas en una pasada. El PCAP resultante se puede pasar
    directamente a analizar_ies_pcap para el detalle completo de IEs de cada AP.

    interfaz    -- interfaz WiFi en modo managed (por defecto 'wlan0').
    frecuencias -- lista separada por comas en MHz (ej: '2437,5180'). Vacio = todas.
    pasivo      -- True (por defecto) para escaneo pasivo, sin emitir probe requests.
    nombre      -- nombre del fichero .pcap. Si se omite se genera con timestamp.
    """
    err = _validar_interfaz(interfaz)
    if err:
        return err
    if not _scandump_disponible():
        return (f"scandump no esta instalado en {_SCANDUMP_BIN}.\n"
                "Instalalo en el host con:\n"
                "  sudo apt-get install -y build-essential libnl-genl-3-dev libpcap-dev\n"
                "  git clone https://github.com/WLAN-Pi/scandump && cd scandump && make\n"
                "  sudo install -m 755 scandump /usr/local/bin/scandump\n"
                "  sudo setcap cap_net_admin+ep /usr/local/bin/scandump\n"
                "Mientras tanto, escanear_ssid() sigue funcionando via 'iw scan'.")

    if nombre:
        if not PCAP_VALIDO.match(nombre):
            return f"Nombre no valido: '{nombre}'. Usa algo como 'mi_scan.pcap'."
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        nombre = f"scan_{interfaz}_{ts}.pcap"
    ruta, err = _ruta_pcap_segura(nombre)
    if err:
        return err

    err = _ejecutar_scandump(interfaz, ruta, frecuencias, pasivo)
    if err:
        return err
    try:
        os.chmod(ruta, 0o644)
    except OSError:
        pass

    redes, err_lec = _recolectar_scan_pcap(ruta)
    resumen = (f"Escaneo guardado: {nombre}\nRuta: {ruta}\n"
               f"Tamano: {os.path.getsize(ruta)} bytes\n"
               f"Modo: {'pasivo' if pasivo else 'activo'} | "
               f"Frecuencias: {frecuencias or 'todas'}\n")
    if err_lec:
        return resumen + f"\n{err_lec}"
    resumen += f"APs unicos: {len(redes)}\n\nUsa analizar_ies_pcap('{nombre}') para el detalle de IEs."
    return resumen


def _escanear_ssid_scandump(interfaz: str, ssid: str) -> str | None:
    """Camino scandump de escanear_ssid. Devuelve None si scandump falla, para que
    el llamante pueda caer al parseo clasico de 'iw scan'."""
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix="scan_", suffix=".pcap")
    os.close(fd)
    try:
        if _ejecutar_scandump(interfaz, tmp):
            return None
        redes, err = _recolectar_scan_pcap(tmp)
        if err or not redes:
            return None
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return _formatear_redes(redes, ssid, "scandump")


def _formatear_redes(redes: list, ssid: str, via: str) -> str:
    """Tabla comun a los dos caminos de escaneo. El filtro de SSID es por subcadena
    e insensible a mayusculas, igual que en analizar_ies_pcap.

    Deduplica por BSSID quedandose con la primera aparicion: 'iw scan' puede listar
    el mismo BSS varias veces (entradas de cache de barridos distintos), lo que antes
    inflaba el recuento de redes."""
    unicas, vistos = [], set()
    for r in redes:
        bssid = (r.get("bssid") or "").lower()
        if not bssid or bssid in vistos:
            continue
        vistos.add(bssid)
        unicas.append(r)
    redes = unicas

    if ssid:
        redes = [r for r in redes if ssid.lower() in (r.get("ssid") or "").lower()]
        if not redes:
            return f"No se encontro ninguna red cuyo SSID contenga '{ssid}'."
    if not redes:
        return "No se detecto ninguna red."

    def _clave(r):
        try:
            return int(r.get("freq") or 0)
        except (ValueError, TypeError):
            return 0

    out = [f"=== Redes{f' con SSID que contiene {ssid!r}' if ssid else ''}: "
           f"{len(redes)} (via {via}) ==="]
    for r in sorted(redes, key=_clave):
        canal = r.get("canal") or _freq_a_canal(r.get("freq", ""))
        nombre = r.get("ssid") or "(oculto)"
        seg = r.get("seguridad") or "abierta/?"
        out.append(f"SSID: {nombre:<20} | BSSID: {r['bssid']} | Canal: {canal:<4} | "
                   f"Freq: {r.get('freq', '')} MHz | Senal: {r.get('signal', '')} dBm | Seg: {seg}")
    return "\n".join(out)


@mcp.tool()
def escanear_ssid(interfaz: str = "wlan0", ssid: str = "") -> str:
    """Escanea redes WiFi y muestra BSSID, canal, frecuencia y senal de cada AP.
    Si se indica un SSID, filtra por las redes cuyo nombre lo contenga.

    interfaz: interfaz WiFi en modo managed (ej: 'wlan0').
    ssid: texto a buscar en el nombre de red (subcadena, insensible a mayusculas).
          Vacio = todas.

    Usa scandump si esta instalado (decodifica la seguridad con el IE RSN real);
    si no, cae automaticamente al parseo de texto de 'iw scan'.
    """
    err = _validar_interfaz(interfaz)
    if err:
        return err
    if _scandump_disponible():
        resultado = _escanear_ssid_scandump(interfaz, ssid)
        if resultado is not None:
            return resultado
        # scandump instalado pero fallo: se sigue por el camino clasico.
    return _escanear_ssid_iw(interfaz, ssid)


def _escanear_ssid_iw(interfaz: str, ssid: str) -> str:
    """Camino clasico: parsea la salida de texto de 'iw scan'. Se mantiene como
    fallback porque no depende de que scandump este instalado."""
    salida = _run(["iw", "dev", interfaz, "scan"], timeout=25, usar_sudo=True)
    if salida.startswith(("Error", "Timeout", "Comando no encontrado")):
        return salida

    redes, actual = [], {}
    for linea in salida.split("\n"):
        l = linea.strip()
        # Exigir una MAC: el IE "BSS Load:" tambien empieza por "BSS " y antes se
        # tomaba por un BSS nuevo, creando una red fantasma y ademas truncando el
        # registro del AP que venia parseandose.
        m_bss = re.match(r"^BSS ([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", l)
        if m_bss:
            if actual:
                redes.append(actual)
            actual = {"bssid": m_bss.group(1), "ssid": "", "freq": "",
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
    return _formatear_redes(redes, ssid, "iw scan")


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
# 7. Analisis de IEs HT/VHT/HE/EHT desde pcap (scapy, sin wlan_mgt.*)
# ---------------------------------------------------------------------------

# ── IDs de Information Elements 802.11 ──────────────────────────────────────
# Las posiciones de bit de los IEs de roaming (54/70/127), RSNX (244) y los
# extendidos de Wi-Fi 6E/7 (59/106/107) siguen la especificacion destilada en
# CAPABILITY_LOGIC.md del proyecto wlanpi-profiler (BSD-3-Clause):
# https://github.com/WLAN-Pi/wlanpi-profiler/blob/main/CAPABILITY_LOGIC.md
_IE_SSID               = 0
_IE_SUPPORTED_CHANNELS = 6
_IE_DS_PARAM           = 3
_IE_POWER_CAPABILITY   = 33
_IE_RSN                = 48
_IE_HT_CAPABILITIES    = 45
_IE_MOBILITY_DOMAIN    = 54    # presencia => 802.11r (fast transition)
_IE_HT_OPERATION       = 61
_IE_RM_ENABLED_CAPS    = 70    # presencia => 802.11k (radio resource mgmt)
_IE_EXTENDED_CAPS      = 127   # 802.11v (BSS Transition), SCS, MSCS
_IE_VHT_CAPABILITIES   = 191
_IE_VHT_OPERATION      = 192
_IE_RSNX               = 244   # SAE H2E (WPA3)
_IE_EXTENSION          = 255   # Wi-Fi 6/6E/7 usan IE extendido
_IE_EXT_HE_CAP         = 35    # sub-ID dentro de IE 255
_IE_EXT_HE_6GHZ_CAPS   = 59    # sub-ID: presencia => Wi-Fi 6E
_IE_EXT_EHT_CAP        = 106   # sub-ID: presencia => Wi-Fi 7 (802.11be)
_IE_EXT_MULTI_LINK     = 107   # sub-ID: MLO

_RSN_CIPHER_SUITES = {
    1: "WEP-40", 2: "TKIP", 4: "CCMP-128 (AES)", 5: "WEP-104",
    6: "BIP-CMAC-128", 8: "GCMP-128", 9: "GCMP-256", 10: "CCMP-256",
    11: "BIP-GMAC-128", 12: "BIP-GMAC-256", 13: "BIP-CMAC-256",
}

_RSN_AKM_SUITES = {
    1: "802.1X (WPA2-Enterprise)", 2: "PSK (WPA2-Personal)",
    3: "FT-802.1X", 4: "FT-PSK", 5: "802.1X-SHA256", 6: "PSK-SHA256",
    7: "TDLS", 8: "SAE (WPA3-Personal)", 9: "FT-SAE",
    11: "802.1X-SuiteB-SHA256", 12: "802.1X-SuiteB-SHA384",
    13: "FT-802.1X-SHA384", 14: "FILS-SHA256", 15: "FILS-SHA384",
    16: "FT-FILS-SHA256", 17: "FT-FILS-SHA384", 18: "OWE",
}


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
    # Cada octeto del Rx MCS set cubre un spatial stream (byte 0 = MCS 0-7 = 1SS,
    # byte 1 = MCS 8-15 = 2SS, ...). Basta con que el octeto sea distinto de cero:
    # exigir == 0xFF daba nss=0 en radios que anuncian un MCS set parcial.
    nss = 0
    mcs_parcial = False
    for i, byte_val in enumerate(rx_mcs_bitmask[:4]):
        if byte_val:
            nss = i + 1
            if byte_val != 0xFF:
                mcs_parcial = True
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
        "rx_mcs_set_parcial": mcs_parcial,
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


def _rsn_suite_nombre(tabla: dict, data: bytes, offset: int) -> str:
    if offset + 4 > len(data):
        return "?"
    oui = data[offset:offset + 3]
    tipo = data[offset + 3]
    nombre = tabla.get(tipo, f"desconocido({tipo})")
    if oui != b"\x00\x0f\xac":
        return f"{nombre} (OUI no estandar: {oui.hex()})"
    return nombre


def _decode_rsn_ie(data: bytes) -> dict:
    """Decodifica el IE RSN (48): version, cipher de grupo/pairwise, AKM suites y PMF."""
    if len(data) < 8:
        return {"error": f"IE RSN demasiado corto ({len(data)} bytes, esperado >=8)"}
    version = struct.unpack_from("<H", data, 0)[0]
    group_cipher = _rsn_suite_nombre(_RSN_CIPHER_SUITES, data, 2)
    off = 6
    pairwise_count = struct.unpack_from("<H", data, off)[0]
    off += 2
    pairwise = []
    for _ in range(pairwise_count):
        pairwise.append(_rsn_suite_nombre(_RSN_CIPHER_SUITES, data, off))
        off += 4

    resultado = {
        "version": version, "group_cipher": group_cipher, "pairwise_ciphers": pairwise,
        "akm_suites": [], "pmf_capable": None, "pmf_required": None,
    }
    if off + 2 > len(data):
        resultado["nota"] = "IE truncado antes de AKM suites"
        return resultado

    akm_count = struct.unpack_from("<H", data, off)[0]
    off += 2
    for _ in range(akm_count):
        resultado["akm_suites"].append(_rsn_suite_nombre(_RSN_AKM_SUITES, data, off))
        off += 4

    if off + 2 <= len(data):
        rsn_cap = struct.unpack_from("<H", data, off)[0]
        resultado["preauth"] = bool(_bit(rsn_cap, 0))
        resultado["pmf_required"] = bool(_bit(rsn_cap, 6))
        resultado["pmf_capable"] = bool(_bit(rsn_cap, 7))
    return resultado


def _decode_he_capabilities(data: bytes) -> dict:
    # Minimo valido = 6 (MAC) + 11 (PHY) + 4 (MCS/NSS <=80MHz) = 21 bytes.
    # El umbral anterior (22) descartaba IEs HE minimos pero legitimos.
    if len(data) < 21:
        return {"error": f"IE HE demasiado corto ({len(data)} bytes, esperado >=21)"}
    mac_cap = int.from_bytes(data[0:6], "little")
    phy_cap = int.from_bytes(data[6:17], "little")
    mcs_nss = data[17:]
    # HE PHY Capabilities: B1-B7 son el Channel Width Set (802.11ax).
    #   B1 = 40 MHz en 2.4 GHz          B2 = 40/80 MHz en 5/6 GHz
    #   B3 = 160 MHz en 5/6 GHz         B4 = 160/80+80 MHz en 5/6 GHz
    # Antes se etiquetaba B1 como "<=80 MHz", que es justo la banda equivocada.
    ch_width_set = _bits(phy_cap, 1, 7)

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
        "bw_40mhz_2ghz": bool(_bit(ch_width_set, 0)),
        "bw_40_80mhz_5_6ghz": bool(_bit(ch_width_set, 1)),
        "bw_160mhz_5_6ghz": bool(_bit(ch_width_set, 2)),
        "bw_160_80p80mhz_5_6ghz": bool(_bit(ch_width_set, 3)),
        # SU/MU beamforming viven en B31/B32/B33 del PHY, no en 48/49/50.
        "su_beamformer": bool(_bit(phy_cap, 31)),
        "su_beamformee": bool(_bit(phy_cap, 32)),
        "mu_beamformer": bool(_bit(phy_cap, 33)),
        "mcs_nss_map_80mhz": mcs_map,
    }


def _ext_cap_bit(data: bytes, bit: int) -> bool:
    """Lee un bit del IE 127, cuya numeracion es global sobre el array de octetos."""
    octeto, desplaz = divmod(bit, 8)
    if octeto >= len(data):
        return False
    return bool(_bit(data[octeto], desplaz))


def _decode_extended_caps(data: bytes) -> dict:
    """IE 127 (Extended Capabilities). El bit 19 es el que confirma 802.11v."""
    if not data:
        return {"error": "IE Extended Capabilities vacio"}
    return {
        "longitud_octetos": len(data),
        "proxy_arp": _ext_cap_bit(data, 12),
        "wnm_sleep_mode": _ext_cap_bit(data, 17),
        "bss_transition_11v": _ext_cap_bit(data, 19),
        "multiple_bssid": _ext_cap_bit(data, 22),
        "scs": _ext_cap_bit(data, 54),
        "mscs": _ext_cap_bit(data, 85),
    }


def _decode_rsnx(data: bytes) -> dict:
    """IE 244 (RSNX). Relevante en WPA3: SAE Hash-to-Element."""
    if not data:
        return {"error": "IE RSNX vacio"}
    b0 = data[0]
    return {
        "field_length": _bits(b0, 0, 3) + 1,
        "protected_twt": bool(_bit(b0, 4)),
        "sae_hash_to_element": bool(_bit(b0, 5)),
    }


def _decode_supported_channels(data: bytes) -> dict:
    """IE 6. Pares (primer canal, nº de canales). El paso entre canales es 1 en
    2.4 GHz y 4 en 5 GHz, asi que cada par se expande con su propio paso."""
    canales = []
    for i in range(0, len(data) - 1, 2):
        primero, cuantos = data[i], data[i + 1]
        paso = 1 if primero <= 14 else 4
        canales.extend(primero + n * paso for n in range(cuantos))
    bandas = []
    if any(c <= 14 for c in canales):
        bandas.append("2.4 GHz")
    if any(c > 14 for c in canales):
        bandas.append("5 GHz")
    return {"canales": canales, "bandas": bandas, "total": len(canales)}


def _decode_power_capability(data: bytes) -> dict:
    """IE 33. Potencia TX minima y maxima del cliente, en dBm con signo."""
    if len(data) < 2:
        return {"error": f"IE Power Capability demasiado corto ({len(data)} bytes)"}
    return {
        "tx_power_min_dbm": struct.unpack_from("<b", data, 0)[0],
        "tx_power_max_dbm": struct.unpack_from("<b", data, 1)[0],
    }


def _decode_eht_capabilities(data: bytes) -> dict:
    """IE extendido 106 (802.11be / Wi-Fi 7). `data` llega ya sin el byte de sub-ID.

    Offsets segun CAPABILITY_LOGIC.md de wlanpi-profiler, que los numera sobre el
    tag crudo (incluyendo ID+longitud+sub-ID): su "octeto 3" es aqui data[0].
    """
    if len(data) < 2:
        return {"error": f"IE EHT demasiado corto ({len(data)} bytes, esperado >=2)"}
    mac0, mac1 = data[0], data[1]
    resultado = {
        "epcs_priority_access": bool(_bit(mac0, 0)),
        "eht_om_control": bool(_bit(mac0, 1)),
        "restricted_twt": bool(_bit(mac1, 3)),
        "scs_traffic_description": bool(_bit(mac1, 4)),
    }
    # PHY capabilities = 9 octetos desde data[2]; el "octeto 11" del tag es data[8].
    if len(data) >= 9:
        phy_o11 = data[8]
        resultado["eht_dup_mcs14_6ghz"] = bool(_bit(phy_o11, 3))
        resultado["mcs15_support"] = _bits(phy_o11, 4, 7)
    return resultado


def _decode_multi_link(data: bytes) -> dict:
    """IE extendido 107 (Multi-Link Element, MLO de 802.11be).

    El Common Info es de longitud VARIABLE segun el mapa de presencia del campo
    Multi-Link Control, asi que hay que recorrerlo campo a campo. Si los limites
    no cuadran se degrada a "MLO presente" sin desglose, en vez de inventar offsets.
    """
    if len(data) < 2:
        return {"error": f"IE Multi-Link demasiado corto ({len(data)} bytes)"}
    mlc = struct.unpack_from("<H", data, 0)[0]
    tipos = {0: "Basic", 1: "Probe Request", 2: "Reconfiguration",
             3: "TDLS", 4: "Priority Access"}
    tipo = _bits(mlc, 0, 2)
    presencia = _bits(mlc, 4, 15)
    resultado = {"mlo_presente": True, "tipo": tipos.get(tipo, f"reservado({tipo})")}
    if tipo != 0:
        return resultado          # solo el Basic lleva el Common Info que interesa
    if len(data) < 9:
        resultado["nota"] = "Common Info truncado antes de la MLD MAC"
        return resultado

    resultado["mld_mac"] = ":".join(f"{b:02x}" for b in data[3:9])
    off = 9
    if _bit(presencia, 0):        # Link ID Info
        off += 1
    if _bit(presencia, 1):        # BSS Parameters Change Count
        off += 1
    if _bit(presencia, 2):        # Medium Synchronization Delay
        off += 2
    if _bit(presencia, 3):        # EML Capabilities
        if off + 2 <= len(data):
            eml = struct.unpack_from("<H", data, off)[0]
            resultado["emlsr_support"] = bool(_bit(eml, 0))
            resultado["emlmr_support"] = bool(_bit(eml, 7))
        off += 2
    if _bit(presencia, 4):        # MLD Capabilities and Operations
        if off + 2 <= len(data):
            mld = struct.unpack_from("<H", data, off)[0]
            # El campo codifica "maximo de enlaces simultaneos menos 1".
            resultado["max_enlaces_simultaneos"] = _bits(mld, 0, 3) + 1
            resultado["reconfiguracion"] = bool(_bit(mld, 6))
            resultado["tid_to_link_negociacion"] = _bits(mld, 10, 11)
        off += 2
    if off > len(data):
        resultado["nota"] = "Common Info mas corto de lo que anuncia su mapa de presencia"
    return resultado


# ── Identificacion de fabricante y MAC aleatorizada ─────────────────────────
# El fichero OUI lo aporta el paquete Debian 'ieee-data'. Si no esta instalado,
# el perfilado sigue funcionando sin nombre de fabricante (no es un requisito).
_OUI_FICHEROS = ["/usr/share/ieee-data/oui.txt", "/var/lib/ieee-data/oui.txt"]
_oui_cache = None


def _cargar_oui() -> dict:
    """Carga y cachea el mapa OUI->fabricante. Se lee una sola vez por proceso."""
    global _oui_cache
    if _oui_cache is not None:
        return _oui_cache
    _oui_cache = {}
    for ruta in _OUI_FICHEROS:
        if not os.path.exists(ruta):
            continue
        try:
            with open(ruta, "r", encoding="utf-8", errors="replace") as fh:
                for linea in fh:
                    if "(hex)" not in linea:
                        continue
                    izq, _, der = linea.partition("(hex)")
                    prefijo = izq.strip().replace("-", ":").lower()
                    nombre = der.strip()
                    if len(prefijo) == 8 and nombre:
                        _oui_cache[prefijo] = nombre
        except Exception:
            pass
        break
    return _oui_cache


def _fabricante(mac: str) -> str:
    return _cargar_oui().get(mac.lower()[:8], "")


def _mac_aleatorizada(mac: str) -> bool:
    """True si la MAC es localmente administrada (bit 1 del primer octeto), que es
    como se anuncian las MAC aleatorizadas de moviles. Atajo equivalente que usa
    wlanpi-profiler: el segundo digito hex es 2, 6, a o e."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


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
        elif ie_id == _IE_RSN:
            ies["rsn"] = _decode_rsn_ie(ie_data)
        elif ie_id == _IE_HT_CAPABILITIES:
            ies["ht_capabilities"] = _decode_ht_capabilities(ie_data)
        elif ie_id == _IE_HT_OPERATION:
            ies["ht_operation"] = _decode_ht_operation(ie_data)
        elif ie_id == _IE_VHT_CAPABILITIES:
            ies["vht_capabilities"] = _decode_vht_capabilities(ie_data)
        elif ie_id == _IE_VHT_OPERATION:
            ies["vht_operation"] = _decode_vht_operation(ie_data)
        elif ie_id == _IE_SUPPORTED_CHANNELS:
            ies["supported_channels"] = _decode_supported_channels(ie_data)
        elif ie_id == _IE_POWER_CAPABILITY:
            ies["power_capability"] = _decode_power_capability(ie_data)
        elif ie_id == _IE_MOBILITY_DOMAIN:
            # La sola presencia del IE confirma 802.11r.
            ies["mobility_domain_11r"] = True
        elif ie_id == _IE_RM_ENABLED_CAPS:
            # La sola presencia del IE confirma 802.11k.
            ies["rm_enabled_11k"] = True
        elif ie_id == _IE_EXTENDED_CAPS:
            ies["extended_caps"] = _decode_extended_caps(ie_data)
        elif ie_id == _IE_RSNX:
            ies["rsnx"] = _decode_rsnx(ie_data)
        elif ie_id == _IE_EXTENSION and ie_len >= 1:
            sub_id = ie_data[0]
            if sub_id == _IE_EXT_HE_CAP:
                ies["he_capabilities"] = _decode_he_capabilities(ie_data[1:])
            elif sub_id == _IE_EXT_HE_6GHZ_CAPS:
                # Presencia => la radio opera en 6 GHz (Wi-Fi 6E).
                ies["he_6ghz_band_caps"] = True
            elif sub_id == _IE_EXT_EHT_CAP:
                ies["eht_capabilities"] = _decode_eht_capabilities(ie_data[1:])
            elif sub_id == _IE_EXT_MULTI_LINK:
                ies["multi_link"] = _decode_multi_link(ie_data[1:])

        i += 2 + ie_len
    return ies


def _recolectar_aps_pcap(ruta: str, filtro_ssid: str = "",
                         filtro_bssid: str = "") -> tuple[dict, str]:
    """Recorre un pcap y devuelve ({BSSID: {'ssid', 'ies'}}, error).

    Es la capa ESTRUCTURADA del analisis de beacons: analizar_ies_pcap la usa para
    renderizar texto, pero el dict queda disponible tal cual para persistir
    resultados y comparar sesiones (Fase 4) sin tener que re-parsear la prosa.

    Usa PcapReader (streaming) en vez de rdpcap, que carga el fichero entero
    en memoria.
    """
    from scapy.all import PcapReader, Dot11, Dot11Beacon, Dot11Elt
    aps = {}
    try:
        with PcapReader(ruta) as lector:
            for pkt in lector:
                if not (pkt.haslayer(Dot11Beacon) and pkt.haslayer(Dot11)):
                    continue
                bssid = pkt[Dot11].addr3
                if not bssid:
                    continue
                bssid = bssid.upper()
                if bssid in aps:
                    continue
                if filtro_bssid and bssid != filtro_bssid.upper():
                    continue
                try:
                    raw_ies = bytes(pkt.getlayer(Dot11Elt))
                except Exception:
                    continue
                ies = _parse_ies(raw_ies)
                ssid = ies.get("ssid", "") or ""
                if filtro_ssid and filtro_ssid.lower() not in ssid.lower():
                    continue
                aps[bssid] = {"ssid": ssid, "ies": ies}
    except Exception as e:
        return {}, f"ERROR al leer el pcap con scapy: {e}"
    return aps, ""


@mcp.tool()
def analizar_ies_pcap(nombre: str,
                      filtro_ssid: str = "",
                      filtro_bssid: str = "") -> str:
    """Extrae y decodifica los IEs 802.11 de los beacons de un .pcap usando scapy.
    No depende de wlan_mgt.* ni de la version de tshark instalada.

    nombre       -- fichero pcap en el directorio de capturas (ej: 'beacons_multimedia.pcap').
                    Usa listar_pcaps() para ver los disponibles.
    filtro_ssid  -- filtrar por SSID (parcial, case-insensitive). Opcional.
    filtro_bssid -- filtrar por BSSID exacto ('AA:BB:CC:DD:EE:FF'). Opcional.

    Devuelve por cada AP unico: generacion Wi-Fi (hasta Wi-Fi 7), soporte de roaming
    asistido 802.11k/r/v, NSS, MCS set, BW, beamforming, LDPC, Short GI, TWT, canal,
    seguridad (cifrado/AKM/PMF via RSN IE + SAE H2E via RSNX) y MLO si lo anuncia.
    """
    try:
        import scapy.all  # noqa: F401  (la importacion real ocurre en el recolector)
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

    aps, err = _recolectar_aps_pcap(ruta, filtro_ssid, filtro_bssid)
    if err:
        return err

    if not aps:
        msg = f"No se encontraron beacons en '{nombre}'"
        if filtro_ssid:
            msg += f" con SSID='{filtro_ssid}'"
        if filtro_bssid:
            msg += f" con BSSID='{filtro_bssid}'"
        return msg + ". Prueba sin filtros."

    lineas = [
        f"=== IEs 802.11 extraidos de '{nombre}' ===",
        f"    {len(aps)} AP(s) unicos encontrados\n",
    ]

    for bssid, info in sorted(aps.items()):
        ies = info["ies"]
        ssid = info["ssid"] or "<oculto>"
        lineas.append("-" * 60)
        lineas.append(f"BSSID : {bssid}")
        lineas.append(f"SSID  : {ssid}")

        ch_ds  = ies.get("ds_channel")
        ch_ht  = ies.get("ht_operation", {}).get("primary_channel")
        ch_vht = ies.get("vht_operation", {}).get("channel_center_0")
        lineas.append(f"Canal : DS={ch_ds}  HT_op={ch_ht}  VHT_center={ch_vht}")

        lineas.append(f"Gen.  : {_generacion_soportada(ies)}")

        # Roaming asistido: 802.11k (vecinos), 802.11r (fast transition), 802.11v (BTM).
        # Los tres se leen por presencia de IE salvo 11v, que es un bit del IE 127.
        tiene_k = bool(ies.get("rm_enabled_11k"))
        tiene_r = bool(ies.get("mobility_domain_11r"))
        tiene_v = bool(ies.get("extended_caps", {}).get("bss_transition_11v"))
        marca = lambda b: "si" if b else "NO"
        lineas.append(f"Roam. : 802.11k={marca(tiene_k)}  "
                      f"802.11r={marca(tiene_r)}  802.11v={marca(tiene_v)}")
        if not (tiene_k or tiene_r or tiene_v):
            lineas.append("        (sin roaming asistido: el cliente decide solo cuando saltar)")

        # RSN / Seguridad (cifrado, AKM, PMF)
        if "rsn" in ies:
            rsn = ies["rsn"]
            lineas.append("\n  [RSN - IE 48 (Seguridad)]")
            if "error" in rsn:
                lineas.append(f"    {rsn['error']}")
            else:
                lineas.append(f"    Cifrado de grupo   : {rsn.get('group_cipher')}")
                lineas.append(f"    Cifrado pairwise   : {', '.join(rsn.get('pairwise_ciphers') or []) or '?'}")
                lineas.append(f"    AKM (autenticacion): {', '.join(rsn.get('akm_suites') or []) or '?'}")
                pmf_r, pmf_c = rsn.get("pmf_required"), rsn.get("pmf_capable")
                if pmf_r is not None:
                    pmf_txt = "Requerido (obligatorio)" if pmf_r else ("Capaz (opcional)" if pmf_c else "No soportado")
                    lineas.append(f"    PMF                : {pmf_txt}")
                if rsn.get("nota"):
                    lineas.append(f"    Nota               : {rsn['nota']}")
        else:
            lineas.append("\n  [RSN - IE 48] : no presente (red abierta o WEP/WPA1)")

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
                lineas.append(f"    BW 40 MHz (2.4GHz) : {he.get('bw_40mhz_2ghz')}")
                lineas.append(f"    BW 40/80 (5/6GHz)  : {he.get('bw_40_80mhz_5_6ghz')}")
                lineas.append(f"    BW 160 MHz         : {he.get('bw_160mhz_5_6ghz')}")
                lineas.append(f"    BW 160/80+80 MHz   : {he.get('bw_160_80p80mhz_5_6ghz')}")
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

        # RSNX (IE 244) - solo interesa si hay WPA3/SAE en juego
        if "rsnx" in ies:
            rsnx = ies["rsnx"]
            lineas.append("\n  [RSNX - IE 244]")
            if "error" in rsnx:
                lineas.append(f"    {rsnx['error']}")
            else:
                lineas.append(f"    SAE Hash-to-Element: {rsnx.get('sae_hash_to_element')}")
                lineas.append(f"    Protected TWT      : {rsnx.get('protected_twt')}")

        # EHT / Wi-Fi 7 (IE 255 ext 106)
        if "eht_capabilities" in ies:
            eht = ies["eht_capabilities"]
            lineas.append("\n  [EHT Capabilities - IE 255 ext 106]  (Wi-Fi 7)")
            if "error" in eht:
                lineas.append(f"    {eht['error']}")
            else:
                lineas.append(f"    EPCS Priority Acc. : {eht.get('epcs_priority_access')}")
                lineas.append(f"    EHT OM Control     : {eht.get('eht_om_control')}")
                lineas.append(f"    Restricted TWT     : {eht.get('restricted_twt')}")
                lineas.append(f"    SCS Traffic Desc.  : {eht.get('scs_traffic_description')}")
                if "mcs15_support" in eht:
                    lineas.append(f"    Soporte MCS 15     : {eht.get('mcs15_support')}")
                    lineas.append(f"    EHT DUP en 6 GHz   : {eht.get('eht_dup_mcs14_6ghz')}")

        # Multi-Link / MLO (IE 255 ext 107)
        if "multi_link" in ies:
            mlo = ies["multi_link"]
            lineas.append("\n  [Multi-Link Element - IE 255 ext 107]  (MLO)")
            if "error" in mlo:
                lineas.append(f"    {mlo['error']}")
            else:
                lineas.append(f"    Tipo               : {mlo.get('tipo')}")
                if mlo.get("mld_mac"):
                    lineas.append(f"    MLD MAC            : {mlo['mld_mac']}")
                if "max_enlaces_simultaneos" in mlo:
                    lineas.append(f"    Max enlaces simult.: {mlo['max_enlaces_simultaneos']}")
                if "emlsr_support" in mlo:
                    lineas.append(f"    EMLSR / EMLMR      : "
                                  f"{mlo.get('emlsr_support')} / {mlo.get('emlmr_support')}")
                if mlo.get("nota"):
                    lineas.append(f"    Nota               : {mlo['nota']}")

        lineas.append("")

    return "\n".join(lineas)


def _generacion_soportada(ies: dict) -> str:
    """Traduce el conjunto de IEs a la generacion Wi-Fi mas alta que anuncia.

    El IE de 6 GHz (ext 59) es lo que separa Wi-Fi 6 de 6E, y el EHT (ext 106) marca
    Wi-Fi 7. Sin HT no es Wi-Fi 4: es 802.11a/b/g."""
    if "eht_capabilities" in ies:
        return "Wi-Fi 7 (802.11be)"
    if "he_capabilities" in ies:
        return "Wi-Fi 6E (802.11ax en 6 GHz)" if ies.get("he_6ghz_band_caps") \
            else "Wi-Fi 6 (802.11ax)"
    if "vht_capabilities" in ies:
        return "Wi-Fi 5 (802.11ac)"
    if "ht_capabilities" in ies:
        return "Wi-Fi 4 (802.11n)"
    return "pre-802.11n (a/b/g)"


@mcp.tool()
def perfilar_cliente_pcap(nombre: str, cliente_mac: str = "", max_clientes: int = 10) -> str:
    """Perfila las capacidades 802.11 de los CLIENTES a partir de sus Association /
    Reassociation Requests dentro de un .pcap. Totalmente pasivo y offline.

    Responde a preguntas del tipo "por que este movil nunca usa 80 MHz", "por que no
    hace roaming asistido" o "por que no negocia WPA3": el cliente declara todo eso en
    la trama de asociacion, asi que basta con capturarla y decodificarla.

    nombre       -- fichero pcap en el directorio de capturas. Usa listar_pcaps().
    cliente_mac  -- filtrar por una MAC de cliente concreta ('AA:BB:CC:DD:EE:FF'). Opcional.
    max_clientes -- limite de clientes distintos a reportar (por defecto 10).

    Requiere que la captura contenga la asociacion: hay que estar en modo monitor y
    en el canal del AP cuando el cliente se une. Si solo hay beacons, usa
    analizar_ies_pcap (que perfila el AP, no el cliente).
    """
    try:
        from scapy.all import PcapReader, Dot11, Dot11AssoReq, Dot11ReassoReq, Dot11Elt
    except ImportError:
        return ("ERROR: scapy no esta instalado en el entorno del servidor "
                "(dentro del venv: /home/usuario/mcp_tshark/mcp_env/bin/pip install scapy)")

    ruta, err = _ruta_pcap_segura(nombre)
    if err:
        return err
    if not os.path.exists(ruta):
        return f"No existe el fichero '{nombre}'. Usa listar_pcaps() para ver los disponibles."
    if cliente_mac:
        err = _validar_mac(cliente_mac)
        if err:
            return err

    objetivo = cliente_mac.lower() if cliente_mac else ""
    clientes: dict = {}
    try:
        # PcapReader va en streaming: no carga el fichero entero en memoria.
        with PcapReader(ruta) as lector:
            for pkt in lector:
                if not (pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11ReassoReq)):
                    continue
                if not pkt.haslayer(Dot11):
                    continue
                mac = (pkt[Dot11].addr2 or "").lower()
                if not mac or (objetivo and mac != objetivo):
                    continue
                if mac in clientes:
                    clientes[mac]["vistas"] += 1
                    continue
                if len(clientes) >= max_clientes:
                    continue
                try:
                    raw_ies = bytes(pkt.getlayer(Dot11Elt))
                except Exception:
                    continue
                clientes[mac] = {
                    "ies": _parse_ies(raw_ies),
                    "ap": (pkt[Dot11].addr1 or "").lower(),
                    "reasoc": bool(pkt.haslayer(Dot11ReassoReq)),
                    "vistas": 1,
                }
    except Exception as e:
        return f"ERROR al leer el pcap con scapy: {e}"

    if not clientes:
        msg = f"No se encontraron Association/Reassociation Requests en '{nombre}'"
        if cliente_mac:
            msg += f" de {cliente_mac}"
        return (msg + ".\nEsta tool necesita la trama de asociacion: captura en modo monitor "
                "y en el canal del AP mientras el cliente se une.")

    lineas = [f"=== Perfil de clientes desde '{nombre}' ===",
              f"    {len(clientes)} cliente(s) con peticion de asociacion\n"]

    for mac, info in sorted(clientes.items()):
        ies = info["ies"]
        lineas.append("-" * 60)
        etiquetas = []
        if _mac_aleatorizada(mac):
            etiquetas.append("MAC ALEATORIZADA (localmente administrada)")
        else:
            fab = _fabricante(mac)
            etiquetas.append(f"fabricante: {fab}" if fab else "fabricante desconocido")
        lineas.append(f"Cliente : {mac}  [{'; '.join(etiquetas)}]")
        lineas.append(f"Hacia AP: {info['ap']}"
                      f"{'  (REASOCIACION)' if info['reasoc'] else ''}"
                      f"  |  peticiones vistas: {info['vistas']}")
        if ies.get("ssid") is not None:
            lineas.append(f"SSID    : {ies.get('ssid') or '<vacio>'}")
        lineas.append(f"Soporta : {_generacion_soportada(ies)}")

        # Roaming asistido declarado por el CLIENTE: es lo que decide si el AP puede
        # empujarlo con un BSS Transition Management Request.
        tiene_k = bool(ies.get("rm_enabled_11k"))
        tiene_r = bool(ies.get("mobility_domain_11r"))
        tiene_v = bool(ies.get("extended_caps", {}).get("bss_transition_11v"))
        marca = lambda b: "si" if b else "NO"
        lineas.append(f"Roaming : 802.11k={marca(tiene_k)}  "
                      f"802.11r={marca(tiene_r)}  802.11v={marca(tiene_v)}")
        if not tiene_v:
            lineas.append("          (sin 802.11v el AP no puede sugerirle cambiar de BSS)")

        # Streams y anchos por generacion
        ht = ies.get("ht_capabilities", {})
        vht = ies.get("vht_capabilities", {})
        he = ies.get("he_capabilities", {})
        if ht and "error" not in ht:
            lineas.append(f"  HT  : {ht.get('rx_spatial_streams')} streams Rx, "
                          f"40MHz={ht.get('channel_width_40mhz')}, LDPC={ht.get('ldpc')}"
                          + ("  [MCS set parcial]" if ht.get("rx_mcs_set_parcial") else ""))
        if vht and "error" not in vht:
            lineas.append(f"  VHT : {vht.get('rx_mcs_map', {}).get('max_spatial_streams')} streams, "
                          f"BW={vht.get('supported_channel_width')}, "
                          f"SU-beamformee={vht.get('su_beamformee')}, "
                          f"MU-beamformee={vht.get('mu_beamformee')}")
        if he and "error" not in he:
            lineas.append(f"  HE  : {he.get('mcs_nss_map_80mhz', {}).get('max_spatial_streams')} streams, "
                          f"40/80MHz(5/6G)={he.get('bw_40_80mhz_5_6ghz')}, "
                          f"160MHz={he.get('bw_160mhz_5_6ghz')}, "
                          f"SU-beamformee={he.get('su_beamformee')}")

        # Bandas y canales que dice soportar (IE 6) y potencia TX (IE 33)
        sc = ies.get("supported_channels")
        if sc:
            bandas = ", ".join(sc.get("bandas") or []) or "?"
            canales = sc.get("canales") or []
            resumen_ch = ", ".join(str(c) for c in canales[:12])
            if len(canales) > 12:
                resumen_ch += f", ... ({len(canales)} en total)"
            lineas.append(f"  Bandas soportadas : {bandas}")
            lineas.append(f"  Canales           : {resumen_ch}")
        pc = ies.get("power_capability")
        if pc and "error" not in pc:
            lineas.append(f"  Potencia TX       : {pc.get('tx_power_min_dbm')} a "
                          f"{pc.get('tx_power_max_dbm')} dBm")

        # Seguridad que PIDE el cliente (no la que ofrece el AP)
        rsn = ies.get("rsn")
        if rsn and "error" not in rsn:
            akm = ", ".join(rsn.get("akm_suites") or []) or "?"
            pmf_r, pmf_c = rsn.get("pmf_required"), rsn.get("pmf_capable")
            pmf_txt = "?" if pmf_r is None else (
                "Requerido" if pmf_r else ("Capaz" if pmf_c else "No soportado"))
            lineas.append(f"  Seguridad pedida  : AKM={akm} | "
                          f"pairwise={', '.join(rsn.get('pairwise_ciphers') or []) or '?'} | PMF={pmf_txt}")
        if ies.get("rsnx", {}).get("sae_hash_to_element"):
            lineas.append("  SAE Hash-to-Element: si (WPA3 moderno)")
        lineas.append("")

    return "\n".join(lineas)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
