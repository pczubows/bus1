from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from os import urandom, remove
from os.path import getsize
from pathlib import Path
from shutil import copyfile
from random import randint

"""
Nakurwiasz sprawko 

Najpierw napisz że robimy w pythonie bo jest super zajebista składnia i biblioteka i w ogóle (wpisz na wiki czemu taki
 zajebisty)

Odpalasz sobie skrypcik na jeden z dwóch sposobów 
1) Albo instalujeszy pythonka (ważne żebyś podczas instalacji zaznaczył że chcesz go dodać do zmiennej PATH) i 
potem odpalasz to sobie w command linie komendą python lab1.py . Ważne żebyś był w tym katalogu i bogo.txt też był 
w katalogu. Wcześniej musisz zainstalować na pythonku bibliotekę kryptograficzną w command linie poleceniem 
pip install cryptography

2) Ściągasz pycharma i odpalasz ten cały folder jak człowiek. Na dole masz konsole. Tak samo instalujesz cryptography
 jeżeli nie odpali ci się venv.
 
 Najpierw masz teścik operacji wykonywany jakże intuicyjnie funkcją test_operations(a, b) a i b to jak każdy debil się 
 domyśli dwie liczby na których będą wykonywane działania . W pliku są juz prykładowe teściki. Pierdolnij screen funkcji 
 i wyników testów. Napisz że python jest dynamicznie typowany i wykrywa czy ma doczynienia z dużą liczbą i odpowiednio 
 dopasowuje procedury. Nie wiem tylko jak pokazać wyniki tych w chujw ielkich liczb bo one zajebują screen ale możesz
    sprobować.
    
 Potem masz testy szyfrowania i deszyfrowania za pomocą funkcji szyfrującej deszyfrującej a także funkcji która pierdoli
 coś w pliku. Analogicznie screeny funkcji jak i plików po zaszyforawniu odszyfrowaniu. Z błednym plikiem zaszyfrowanym 
 albo kluczem. Ciekawostka taka że jak był spierdolony plik w jedym miejscu to potem reszta pliku była dobrze odszyforwana. Jako 
 że nasza funkcja pierdoląca plik losuje punkt w kótrym go pierdoli jeżeli spierdoli jego końcówkę to można nawet odczytać.
 Z kluczem popsutym totalna chujnia. Dodatkowo daj anegdotke że biblioteka zawiere o wiele seksowniejszą implementację 
 szyforwania fermat ale była ona zbuyt dobra dla nas bo weryfikowała też date edycji pliku co nie pozwalałao nam pzetestować
 przypaku z popsutym plikiem. 
 
 Pod koniec funkcja hashująca tez piękna funkcja test hash która korzysta genrate hash. Raz liczy dla dobrego potem 
 generuje popsuty ,liczy hash i wypierdala popsuty plik. Jak abrdzo chcesz mogę zmienić foramt wyświetlania się hashu bo
 drukuje się z xami bo hekasadecymalny. Screeny wszystkiego pierdut bajeczka pierdut. Jak coś to pisz
   
"""
# roszerzone sito euklidesa
def extended_euclidean(a, b):
    u, w, x, z = 1, a, 0, b
    while w != 0:
        if w < z:
            u, x = x, u
            w, z = z, w

        q = w // z
        u -= q*x
        w -= q*z

    if z != 1:
        return 0

    if x < 0:
        x += b

    return x

#test naszych operacji
def test_operations(a, b):
    print(f'{a} + {b} = {a + b}')
    print(f'{a} - {b} = {a - b}')
    print(f'{a} * {b} = {a * b}')
    print(f'{a} * y (mod {b}) = 1 y = {extended_euclidean(a, b)}')


def encrypt(input_file, output_file, key):
    iv = urandom(16)

    with open(input_file, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend()).encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_data = iv + ciphertext

    with open(output_file, 'wb') as f:
        f.write(encrypted_data)


def decrypt(input_file, output_file, key, corrupted=False):
    with open(input_file, 'rb') as f:
        data = f.read()

    iv = data[:16]
    ciphertext = data[16:]

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend()).decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    if corrupted:
        plaintext = padded_plaintext
    else:
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        try:
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        except ValueError:
            print("Invalid padding")

    with open(output_file, 'wb') as f:
        f.write(plaintext)


def generate_key(size):
    return urandom(size)


def corrupt_file(file):
    with open(file, 'r+b') as f:
        f.seek(randint(0, getsize(file) - 1))
        f.write(bytes(randint(0, 5)))


def test_cipher(test_filename, encrypted_filename, decrypted_filename, corrupt = None):
    key = generate_key(32)
    encrypt(test_filename, encrypted_filename, key)
    if corrupt == "file":
        corrupt_file(encrypted_filename)
    elif corrupt == "key":
        key = bytearray(key)
        key[randint(0, len(key))] = randint(0, 255)
        key = bytes(key)

    decrypt(encrypted_filename, decrypted_filename, key, corrupt)


def generate_hash(file):
    with open(file, 'rb') as f:
        data = f.read()

    hash_func = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash_func.update(data)
    return hash_func.finalize()


def test_hash(file, corrupt=False):
    if corrupt:
        original_file_path = Path(file)
        corrupted_file = original_file_path.stem + "_corrupted" + original_file_path.suffix
        copyfile(file, corrupted_file)
        corrupt_file(corrupted_file)
        hash = generate_hash(corrupted_file)
        remove(corrupted_file)
        print(f'Hash uszkodzonego pliku: {str(hash)}')
    else:
        print(f'Hash orginalnego pliku: {str(generate_hash(file))}')


if __name__ == "__main__":
    test_operations(7, 5)
    test_operations(randint(0, 128), randint(0, 128))
    test_operations(randint(0, pow(2, 1024)), randint(0, pow(2, 1024)))
    test_cipher('bogo.txt', 'bogoenc', 'bogodec.txt')
    test_cipher('bogo.txt', 'bogoenc_corr_key', 'bogodec_corr_key', "key")
    test_cipher('bogo.txt', 'bogoenc_corr_file', 'bogodec_corr_file.txt', "file")
    test_hash('bogo.txt')
    test_hash('bogo.txt', True)














