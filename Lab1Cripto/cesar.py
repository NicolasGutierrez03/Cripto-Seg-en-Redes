import sys

def cifrar_cesar(texto, desplazamiento):
    texto_cifrado = ""
    
    for caracter in texto:
        if caracter.isalpha():
            # Determinar si es mayúscula o minúscula para el código ASCII base
            base = 65 if caracter.isupper() else 97
            
            # Aplicar el desplazamiento circular con módulo 26 (letras del alfabeto inglés)
            nuevo_caracter = chr((ord(caracter) - base + desplazamiento) % 26 + base)
            texto_cifrado += nuevo_caracter
        else:
            # Mantener espacios y otros caracteres especiales intactos
            texto_cifrado += caracter
            
    return texto_cifrado

if __name__ == "__main__":
    # Validar que se entreguen exactamente 2 argumentos (más el nombre del script)
    if len(sys.argv) != 3:
        print("Uso: python cesar.py \"Texto a cifrar\" <desplazamiento>")
        sys.exit(1)
        
    texto_original = sys.argv[1]
    
    # Validar que el desplazamiento sea un número
    try:
        desplazamiento = int(sys.argv[2])
    except ValueError:
        print("Error: El desplazamiento debe ser un número entero.")
        sys.exit(1)
        
    resultado = cifrar_cesar(texto_original, desplazamiento)
    print(resultado)
