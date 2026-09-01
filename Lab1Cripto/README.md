Laboratorio 1: Análisis y Exfiltración de Tráfico ICMP / MitM
Repositorio que contiene los scripts en Python desarrollados para el laboratorio de redes y ciberseguridad, enfocados en el cifrado César, la creación de un canal encubierto (Stealth) mediante paquetes ICMP y la intercepción/descifrado (MitM) del tráfico.

Estructura del Repositorio
cesar.py: Cifra cadenas de texto utilizando el algoritmo César con desplazamiento configurable.

pingv4.py: Envía paquetes ICMP Echo Request encubriendo texto cifrado en el payload, manteniendo las cabeceras y patrones idénticos a un comando ping legítimo para evadir sistemas DPI.

readv2.py: Lee capturas de red (.pcapng o .pcap), extrae los payloads encubiertos, aplica fuerza bruta al cifrado César y puntúa los resultados para hallar la llave y el texto en claro.

Requisitos Previos
Sistema operativo Linux (probado en entornos basados en Arch/Debian).

Python 3.x

Dependencias de red (Scapy):

Bash
pip install scapy
Privilegios de administrador (sudo) para el uso de sockets crudos (requerido al enviar paquetes ICMP personalizados y capturar tráfico de red).

Instrucciones de Uso
1. Cifrado César (cesar.py)
Permite cifrar un texto aplicando un desplazamiento numérico, manteniendo los espacios intactos.

Bash
python3 cesar.py "tu_mensaje_aqui" desplazamiento
Ejemplo:

Bash
python3 cesar.py "criptografia y seguridad en redes" 9
2. Generación de Tráfico Stealth (pingv4.py)
Envía pings de referencia, introduce el mensaje cifrado carácter por carácter en el offset 0x08 del payload ICMP (forzando la última letra a 'b') y emula los contadores del kernel para pasar desapercibido.

Bash
sudo python3 pingv4.py "[MENSAJE_CIFRADO]"
Ejemplo:

Bash
sudo python3 pingv4.py "larycxpajorjh bnpdarmjm nw anmnb"
Nota: Recuerda iniciar una captura en Wireshark o tcpdump en tu interfaz de red física antes de ejecutar este script para almacenar el archivo .pcapng.

3. Ataque MitM y Descifrado (readv2.py)
Analiza un archivo de captura de red, extrae los paquetes encubiertos, ejecuta un ataque de fuerza bruta sobre las 25 combinaciones posibles del cifrado César y utiliza un algoritmo de puntuación heurístico en español para identificar automáticamente el mensaje correcto.

Bash
sudo python3 readv2.py cesar.pcapng
