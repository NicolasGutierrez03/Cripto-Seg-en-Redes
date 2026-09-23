# Laboratorio 2: Análisis de Tráfico y Ataques de Fuerza Bruta en DVWA

Repositorio que contiene los scripts en Python y la documentación del laboratorio de redes y ciberseguridad, enfocados en el despliegue del entorno vulnerable DVWA en Docker, el análisis de tráfico con Wireshark, la ejecución de ataques con herramientas especializadas y el desarrollo de un script automatizado.

---

## Estructura del Repositorio

* `DVWA_Script.py`: Script en Python que automatiza un ataque de fuerza bruta HTTP GET contra el módulo vulnerable de autenticación en DVWA (`vulnerabilities/brute/`), inyectando sesiones activas y evaluando aciertos mediante la ausencia de mensajes de error.
* `informe.tex`: Documento fuente en LaTeX que consolida la redacción formal de todas las actividades, análisis de tráfico, capturas y contramedidas del laboratorio.
* `imagenes/`: Carpeta que almacena las capturas de pantalla de Wireshark, consola y evidencias gráficas utilizadas en el informe.

---

## Requisitos Previos

* Sistema operativo Linux (probado en entornos basados en Arch/Debian).
* Python 3.x y librería `requests`.
* Docker (para el despliegue del contenedor vulnerable de DVWA).
* Wireshark (para la captura y análisis de trazas de red).
* Herramientas ofensivas: `Hydra`, `Burp Suite` y `cURL`.

---

## Instrucciones de Uso

### 1. Despliegue de DVWA en Docker
Levanta la aplicación web vulnerable en un contenedor Docker local en el puerto `8080`.

```bash
docker run --rm -it -p 8080:80 vulnerables/web-dvwa
```

---

### 2. Ataques con cURL
Permite enviar peticiones HTTP programáticas para diferenciar las respuestas del servidor entre accesos correctos e incorrectos.

```bash
curl -X GET "http://localhost:8080/vulnerabilities/brute/?username=admin&password=password&Login=Login" -H "Cookie: PHPSESSID=tu_phpsessid; security=low"
```

---

### 3. Ataques con Burp Suite (Intruder)
Permite interceptar, modificar y automatizar peticiones por lotes, analizando el uso de conexiones persistentes (Keep-Alive) y emulando navegadores convencionales.

---

### 4. Ataques con Hydra
Ejecuta ráfagas masivas y concurrentes de alta velocidad utilizando múltiples sockets TCP independientes en paralelo.

```bash
hydra -l admin -P passwords.txt localhost -s 8080 http-get /vulnerabilities/brute/
```

---

### 5. Análisis de Tráfico en Wireshark
Permite inspeccionar de forma empírica las trazas de red sobre la interfaz local (lo), contrastando las firmas de cliente (User-Agent) y los tiempos Delta.

> **Nota:** Recuerda iniciar una captura en Wireshark filtrando por `http` antes de ejecutar las herramientas para respaldar las evidencias del informe.

---

### 6. Script de Fuerza Bruta en Python (`DVWA_Script.py`)
Automatiza el ataque HTTP GET inyectando cookies de sesión y evaluando la ausencia de mensajes de error en el cuerpo de la respuesta.

**Instalación de dependencias:**
```bash
pip install requests
```

**Configuración:**
Abre el archivo `DVWA_Script.py` y actualiza tu sesión activa:
```python
s.cookies.set("PHPSESSID", "tu_phpsessid_activo_aqui")
s.cookies.set("security", "low")
```

**Ejecución:**
```bash
python3 DVWA_Script.py
```
