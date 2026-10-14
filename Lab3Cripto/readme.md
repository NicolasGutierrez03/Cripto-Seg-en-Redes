# Laboratorio 3: Auditoría de Seguridad y Hashing en Bitwarden

Este repositorio público contiene todas las imágenes, capturas de pantalla y códigos utilizados en el informe final, cumpliendo con los requerimientos de entrega de la actividad. El objetivo principal de este laboratorio es analizar la implementación de algoritmos hash desde el lado del cliente (arquitectura Zero-Knowledge) de la plataforma Bitwarden y evaluar su resistencia contra ataques.

## Generación manual del Hash desde la consola

Como parte del análisis, se desarrolló un script en JavaScript que utiliza la Web Crypto API nativa del navegador para replicar con exactitud el proceso de derivación de claves que realiza Bitwarden antes de enviar cualquier dato por la red.

### Instrucciones de ejecución

Para comprobar el funcionamiento del algoritmo por tu cuenta, sigue estos pasos:

1. Abre cualquier navegador web moderno (Chrome, Firefox, Edge, Brave).
2. Accede a las Herramientas para Desarrolladores presionando `F12` (o la combinación `Ctrl + Shift + I`).
3. Dirígete a la pestaña **Console** (Consola).
4. Copia el bloque de código que se encuentra más abajo y pégalo directamente en la consola.
5. Antes de presionar Enter, modifica la última línea del código reemplazando `"CorreoTextoPlano"` y `"ClaveTextoPlano!"` por las credenciales de prueba que utilizaste para registrarte.
6. Presiona `Enter` para ejecutar la función.

### Código JavaScript

```javascript
async function generarHashBitwardenCompleto(email, password, iterations = 600000) {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);
    const saltBytes = encoder.encode(email.toLowerCase().trim());

    // Etapa 1: Clave Maestra local (600.000 iteraciones)
    const baseKey1 = await crypto.subtle.importKey(
        "raw", passwordBytes, { name: "PBKDF2" }, false, ["deriveBits"]
    );
    const masterKeyBits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt: saltBytes, iterations: iterations, hash: "SHA-256" },
        baseKey1, 256
    );

    // Etapa 2: Hash de autenticación para red (1 iteración)
    const masterKeyBytes = new Uint8Array(masterKeyBits);
    const baseKey2 = await crypto.subtle.importKey(
        "raw", masterKeyBytes, { name: "PBKDF2" }, false, ["deriveBits"]
    );
    const masterPasswordHashBits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt: passwordBytes, iterations: 1, hash: "SHA-256" },
        baseKey2, 256
    );

    return btoa(String.fromCharCode(...new Uint8Array(masterPasswordHashBits)));
}

// Ejecucion: Ingresa tus credenciales de prueba aqui
await generarHashBitwardenCompleto("CorreoTextoPlano", "ClaveTextoPlano!");
```

### Resultado esperado

Una vez ejecutado, la consola retornará una cadena de texto codificada en `Base64` (similar a `iytdzQaZd8ViWgOClVnTuifbQpd2q/CNII7pUiQ7siM=`). Este texto es el hash de autenticación final, el cual coincide exactamente con el valor interceptado en el parámetro `password` durante el envío de datos en la herramienta Burp Suite.
