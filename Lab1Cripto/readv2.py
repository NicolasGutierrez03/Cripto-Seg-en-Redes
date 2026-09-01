#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import re
from scapy.all import rdpcap, ICMP

def validar_argumentos():
    """
    Valida que el script se ejecute con los argumentos correctos y que el archivo exista.
    """
    if len(sys.argv) != 2:
        print("Uso: sudo python3 readv2.py <archivo.pcapng>")
        sys.exit(1)
        
    archivo_pcap = sys.argv[1]
    
    if not os.path.isfile(archivo_pcap):
        print(f"Error: El archivo '{archivo_pcap}' no existe.")
        sys.exit(1)
        
    return archivo_pcap

def extraer_mensaje_oculto(archivo_pcap):
    """
    Lee el archivo de captura, filtra los paquetes ICMP Echo Request (type == 8),
    identifica los paquetes encubiertos y extrae el byte en el índice 8 del payload.
    """
    try:
        # Usamos rdpcap para leer el archivo
        paquetes = rdpcap(archivo_pcap)
    except Exception as e:
        print(f"Error al leer el archivo de captura: {e}")
        sys.exit(1)

    bytes_extraidos = bytearray()
    icmp_echo_count = 0

    for pkt in paquetes:
        # Filtrar estrictamente por ICMP Echo Request
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
            icmp_echo_count += 1
            
            # Extracción robusta del payload
            payload = bytes(pkt[ICMP].payload)
            
            # Descartar paquetes cuyo payload tenga menos de 9 bytes
            if len(payload) < 9:
                continue

            # Criterio A: Sequence Number >= 1000
            criterio_a = pkt[ICMP].seq >= 1000
            
            # Criterio B: Payload == 56 bytes Y el byte en offset 0x08 != 0x00
            criterio_b = (len(payload) == 56 and payload[8] != 0x00)

            # Si cumple AL MENOS uno de los dos criterios, es un paquete encubierto
            if criterio_a or criterio_b:
                bytes_extraidos.append(payload[8])

    # Manejo de error si no se encontraron paquetes encubiertos
    if not bytes_extraidos:
        print(f"Error: No se encontraron paquetes ICMP encubiertos.")
        print(f"Se analizaron {icmp_echo_count} paquetes ICMP Echo Request en total.")
        print("Sugerencia: Verifica que la captura contenga el tráfico generado por el emisor.")
        sys.exit(1)

    # Decodificar usando UTF-8 ignorando errores para evitar fallos con bytes basura
    mensaje_cifrado = bytes_extraidos.decode('utf-8', errors='ignore')
    
    # Eliminar saltos de línea (\n o \r)
    mensaje_cifrado = mensaje_cifrado.replace('\n', '').replace('\r', '')

    return mensaje_cifrado

def descifrar_cesar(texto, desplazamiento):
    """
    Aplica el descifrado César a un texto con un desplazamiento dado (0-25).
    Solo afecta a letras [a-z, A-Z]. Conserva espacios y signos de puntuación.
    """
    resultado = []
    for char in texto:
        if char.isalpha():
            # Determinar la base dependiendo de si es mayúscula o minúscula
            base = ord('A') if char.isupper() else ord('a')
            # Fórmula estricta requerida: chr((ord(char) - base - desplazamiento) % 26 + base)
            char_descifrado = chr((ord(char) - base - desplazamiento) % 26 + base)
            resultado.append(char_descifrado)
        else:
            # Los espacios, números y signos de puntuación quedan intactos
            resultado.append(char)
            
    texto_descifrado = "".join(resultado)
    # Aseguramos que no haya saltos de línea
    texto_descifrado = texto_descifrado.replace('\n', '').replace('\r', '')
    
    return texto_descifrado

def calcular_score(texto):
    """
    Evalúa qué tan probable es que el texto esté en español mediante un sistema de puntuación.
    """
    score = 0
    texto_lower = texto.lower()

    # 1. Frecuencias de letras en español
    frecuencias = {
        'e': 14, 'a': 12, 'o': 9, 's': 8, 'r': 7, 'n': 7, 'i': 6,
        'd': 5, 'l': 5, 'c': 4, 't': 4, 'u': 4, 'm': 3, 'p': 3
    }
    for char in texto_lower:
        if char in frecuencias:
            score += frecuencias[char]

    # 2. Palabras clave y Longitud
    palabras_clave = {
        "el", "la", "de", "que", "en", "un", "es", "y", "los", "se", 
        "por", "con", "para", "una", "criptografia", "seguridad", "redes"
    }
    
    palabras = texto.split()
    for palabra in palabras:
        # Limpiar de signos de puntuación (conservar solo caracteres alfabéticos)
        palabra_limpia = "".join(c for c in palabra if c.isalpha()).lower()
        
        if not palabra_limpia:
            continue

        # Palabras clave
        if palabra_limpia in palabras_clave:
            score += 50

        # Longitud de la palabra
        longitud = len(palabra_limpia)
        if 2 <= longitud <= 15:
            score += 5
        elif longitud > 15:
            score -= 10

    # 3. Espacios (Densidad)
    cantidad_espacios = texto.count(' ')
    if cantidad_espacios > 0:
        ratio = len(texto) / cantidad_espacios
        if 4.0 <= ratio <= 8.0:
            score += 20
    else:
        # Si no hay espacios y el texto tiene más de 20 caracteres
        if len(texto) > 20:
            score -= 30

    # 4. Caracteres extraños
    for char in texto:
        val_ascii = ord(char)
        if (val_ascii < 32 or val_ascii > 126) and char not in ['\n', '\r', '\t']:
            score -= 40

    return score

def main():
    # Validar que el programa se ejecute correctamente
    archivo_pcap = validar_argumentos()

    # Extraer el mensaje cifrado de la captura de red
    mensaje_cifrado = extraer_mensaje_oculto(archivo_pcap)

    mejor_score = -float('inf')
    mejor_desplazamiento = 0
    mejor_mensaje = ""
    
    resultados = []

    # Probar desplazamientos del 0 al 25
    for desplazamiento in range(26):
        texto_descifrado = descifrar_cesar(mensaje_cifrado, desplazamiento)
        score = calcular_score(texto_descifrado)
        
        resultados.append((desplazamiento, texto_descifrado, score))
        
        if score > mejor_score:
            mejor_score = score
            mejor_desplazamiento = desplazamiento
            mejor_mensaje = texto_descifrado

    # Imprimir todas las combinaciones con el formato requerido
    for desplazamiento, texto_descifrado, score in resultados:
        if desplazamiento == mejor_desplazamiento:
            # Resaltado ANSI VERDE brillante para el ganador
            print(f"\033[92m\033[1m{desplazamiento:<2}\t{texto_descifrado}\033[0m")
        else:
            # Color estándar
            print(f"{desplazamiento:<2}\t{texto_descifrado}")

    # Bloque de Resumen Final
    print("-" * 60)
    print(f"Mensaje cifrado original : {mensaje_cifrado}")
    print(f"Desplazamiento ganador   : {mejor_desplazamiento}")
    print(f"Score obtenido           : {mejor_score}")
    print(f"Mensaje en claro final   : {mejor_mensaje}")
    print("-" * 60)

if __name__ == "__main__":
    main()

