import sys
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Clave y IV predefinidos para AES-192-CBC
key = bytearray([
    141, 75, 21, 92, 201, 255, 129, 229, 203, 246, 250, 120, 25, 54, 106, 62,
    198, 33, 166, 86, 65, 108, 215, 147
])
iv = bytearray([
    0x1E, 0x39, 0xF3, 0x69, 0xE9, 0xD, 0xB3, 0x3A, 0xA7, 0x3B, 0x44, 0x2B,
    0xBB, 0xB6, 0xB0, 0xB9
])

def decrypt(db, acc):
    with open(db, 'rb') as fh:
        encrypted_data = fh.read()

    m = hashlib.md5()
    m.update(acc.encode('utf-8'))
    md5 = bytearray(m.digest())

    # Modificar la clave con el hash de la cuenta
    for i in range(24):
        key[i] ^= md5[i & 0xF]

    # Descifrado AES
    cipher = AES.new(bytes(key), AES.MODE_CBC, iv=bytes(iv))
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    # Guardar el archivo descifrado
    with open("archivo_descifrado.db", "wb") as out_file:
        out_file.write(decrypted_data)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Uso: python decrypt_whatsapp.py <archivo.crypt5> <nombre_de_usuario> > decrypted.db')
    else:
        decrypt(sys.argv[1], sys.argv[2])