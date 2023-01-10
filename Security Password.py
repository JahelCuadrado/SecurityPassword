import base64
import pyotp
import random
import string
import pyperclip
import shelve
import qrcode
import os
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#Claves secretas
SECRET_KEY1 = ""

SECRET_KEY2 = ""

SECRET_KEY3 = ""

#Seeds secretas
SEED_KEY1 = ""

SEED_KEY2 = ""

SEED_KEY3 = ""

#Cifrado
password_encrypt = ""

# Usamos el password ingresado para generar una clave de cifrado
salt = b'\xea\x8e\x9d\xed\xe5\x91?\x08\x02\xdc\x96\xf1\x8a\x9d\x1e'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256,
    iterations=100000,
    length=32,
    salt=salt,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password_encrypt.encode()))

# Creamos un objeto Fernet con la clave generada
f = Fernet(key)


# Abrimos un archivo shelve llamado 'secret.db' en modo lectura/escritura
with shelve.open('secret.db', flag='c') as db:
    
    # Verificamos si existe una clave 'secret' en el archivo
    if 'secret' not in db:
        
        # Si la clave no existe, pedimos al usuario que proporcione su clave secreta de Google Authenticator
        secret = ''.join(random.choices(string.ascii_letters + string.digits, k=200))
        
        # Ciframos el secreto utilizando Fernet
        secret_cifrado = f.encrypt(secret.encode())
        
        # Almacenamos la clave secreta en el archivo
        db['secret'] = secret_cifrado

# Abrimos de nuevo el archivo shelve en modo lectura
with shelve.open('secret.db', flag='c') as db:
    
    # Recuperamos la clave secreta almacenada en el archivo
    secret = f.decrypt(db['secret']) 
    secret = secret.decode()
    secret += SECRET_KEY1
    secret += SECRET_KEY2
    secret += SECRET_KEY3
    
    random.seed(secret)
    secret = ''.join(random.choices(string.ascii_letters, k=200))

    # Creamos un objeto TOTP (Time-Based One-Time Password) utilizando la clave secreta
    totp = pyotp.TOTP(secret)
    
    # Verificamos si existe una clave 'qr' en el archivo
    if 'qr' not in db:
        
        # Genera el URI del código QR
        uri = totp.provisioning_uri("", issuer_name="Security Password")
        
        # Crea un objeto QRcode
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        
        # Agrega el URI al objeto QRcode
        qr.add_data(uri)
        qr.make(fit=True)

        # Genera la imagen del código QR
        img = qr.make_image(fill_color="black", back_color="white")

        # Guarda la imagen en un archivo
        img.save("codigo_qr.png")
        
        im = Image.open("codigo_qr.png")
        im.show()
        
        db['qr'] = True
    
    
code = input("Ingrese su código de Google Authenticator: ")

# Verificamos que el código OTP proporcionado sea válido
if totp.verify(code):
    
    #Borramos el código QR
    os.remove("codigo_qr.png")
    
    # Si el código OTP es válido, generamos una contraseña aleatoria a partir de la semilla
    def generate_password(seed):
        
            # Usamos la semilla para inicializar el generador de números aleatorios
            random.seed(seed)

            # Generamos una lista de símbolos que incluye todos los símbolos menos el punto y el punto y coma
            symbols = string.punctuation.replace(".", "").replace(";", "").replace('"', "")

            # Generamos una contraseña aleatoria de 100 caracteres con mayúsculas, minúsculas, dígitos y símbolos
            password = ''.join(random.choices(string.ascii_letters + string.digits + symbols, k=100))
            return password

    # Generamos la semilla a partir de la clave introducida y las tres SECRET_KEY
    seed = input("Ingrese una semilla: ")
    seed += secret
    seed += SEED_KEY1
    seed += SEED_KEY2
    seed += SEED_KEY3

    # Generamos una contraseña aleatoria a partir de la semilla
    password = generate_password(seed)

    # Copiamos la contraseña en el portapapeles
    pyperclip.copy(password)
    
else:
    # Si el código OTP no es válido, mostramos un mensaje de error
    print("Código OTP no válido")
