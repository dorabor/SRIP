# Sigurnost računala i podataka : izvještaji

## 1. laboratorijska vježba

Upoznali smo se s alatima gitHub i Docker.

Aplikaciju Docker koristimo preko Windows terminala, međutim također je moguće i preko Command Prompta iz razloga sto je docker open source aplikacija napisana za oen source OS Linux, a navedeni alati su tome najbliži.

Za izvršavanje napada man in the middle smo prvo kreirali naredobom mkdir svoje datoteke u koje želimo klinirati zadani git repozitorij naredbom git clone.

Unutar repozitorija imamo naredbe [start.sh](http://start.sh) i stop.sh.

Nakon pokretanja docker konejnera naredbom docker ps lako pogledamo u svakom trenutku sta smo točno sve pokrenuli.

Imamo 3 pokrenuta kontjenera : station-1, station-2 i evil-station.

Uspostavljamo komunikacijski kanal između station-1 i station-2 koristeći netcat, otvaeamo server TCP socket na portu 9000.

Zatim pokrentanjem evil station kontjenera kotistimo naredbu arspoof kojom presretamo komunikacijski kanal, međutim nemamo nikakve informacije, ni da li komuniciraju, a ni sta komuniciraju.

Međutm pokretanjem tcpdump u evil station kontjeneru prethodne navedene stavke i informacije o komunikaciji dobivamo.

## 2. laboratorijska vjezba

Radili smo enkipciju i dekripciju informacija

import base64from cryptography.fernet import Fernetfrom cryptography.hazmat.primitives import 

hashesdef hash(input):if not isinstance(input, bytes):input = input.encode()

digest = hashes.Hash(hashes.SHA256())digest.update(input)

hash = digest.finalize()

return hash.hex()

def test_png(header):

if header.startswith(b"\211PNG\r\n\032\n"):

return True

def brute_force():

# Reading from a filefilename = "b36eb2046b0804d36e4a3cc7b62214fe8a880143ac7b063329ec769574364113.encrypted"with open(filename, "rb") as file:ciphertext = file.read()# Now do something with the ciphertextctr = 0

while True:key_bytes = ctr.to_bytes(32, "big")key = base64.urlsafe_b64encode(key_bytes)

if not (ctr + 1) % 1000:

print(f"[*]keys tested: {ctr +1:,}", end="\r")

# Now initialize the Fernet system with the given key# and try to decrypt your challenge.# Think, how do you know that the key tested is the correct key# (i.e., how do you break out of this infinite loop)?

try:plaintext = Fernet(key).decrypt(ciphertext)header = plaintext[:32]

if test_png(header):print(f"[+]KEY FOUND: {key}")

# Writing to a filewith open("BINGO.png", "wb") as file:file.write("plaintext")break

except Exception:passctr += 1if __name__ == "__main__":#otkrivas ime tvog filea:

#h=hash('boric_dora')

#print(h)brute_force()

## 3.Laboratorijska vjezba

Kod:

from cryptography.hazmat.primitives import hashes, hmac

from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.primitives.asymmetric import padding

import os

from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.backends import default_backend

def generate_MAC(key, message):

if not isinstance(message, bytes):

message = message.encode()

h = hmac.HMAC(key, hashes.SHA256())

h.update(message)

signature = h.finalize()

return signature

def verify_MAC(key, signature, message):

if not isinstance(message, bytes):

message = message.encode()

h = hmac.HMAC(key, hashes.SHA256())

h.update(message)

try:

h.verify(signature)

except InvalidSignature:

return False

else:

return True

def verify_signature_rsa(signature, message):

PUBLIC_KEY = load_public_key()

try:

PUBLIC_KEY.verify(

signature,

message,

padding.PSS(

mgf=padding.MGF1(hashes.SHA256()),

salt_length=padding.PSS.MAX_LENGTH

),

hashes.SHA256()

)

except InvalidSignature:

return False

else:

return True

def load_public_key(PUBLIC_KEY_FILE):

with open(PUBLIC_KEY_FILE, "rb") as f:

PUBLIC_KEY = serialization.load_pem_public_key(

f.read(),

backend=default_backend()

)

return PUBLIC_KEY

if __name__=="__main__":

key = "boric_dora".encode()

path = os.path.join("challenges", "boric_dora", "mac_challenge")

print(path)

#with open("message.txt", "rb") as file:

# content = file.read()

# mac = generate_MAC(key, content)

# with open("message.sig", "wb") as file:

# file.write(mac)

#with open("message.sig", "rb") as file:

# signature = file.read()

#is_authentic = verify_MAC(key,signature, content)

#print(is_authentic)

for ctr in range(1, 11):

msg_filename = f"order_{ctr}.txt"

file_path_msg = os.path.join(path, msg_filename)

sig_filename = f"order_{ctr}.sig"

file_path_sig = os.path.join(path, sig_filename)

with open(file_path_msg, "rb") as file:

content_file = file.read()

with open(file_path_sig, "rb") as file:

signature = file.read()

is_authentic = verify_MAC(key,signature, content_file)

print(f'Message {content_file.decode():>45} {"OK" if is_authentic else "NOK":<6}')

## 4.laboratorijska vjezba
U ovoj vjezbi smo se bavili osnovnim konceptima za sigurnu pohranu lozinki. Uspoređujemo klasične/brze/kriptografske hash fje s specijaliziranim kriptografskim fjama za sigurnu pohranu zaporki i izvođenje enkripcijskih ključeva(KDF).

Pa tako imamo sljedeće:

# Linux Hash fja

Početna vrijednost broja iteracija za ovu fju je postavljena na 5000 i za 1000000 iteracija. S varijablom Rounds postavljamo željeni broj iteracija.

Cilj je kripto fje koje se koriste za pohranu lozinki uciniti što sporijima, tako da napadaču pri npr offline napadu bude što teže

kod koji smo koriszili:

from os import urandom
from prettytable import PrettyTable
from timeit import default_timer as time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from passlib.hash import sha512_crypt, pbkdf2_sha256, argon2


def time_it(function):
    def wrapper(*args, **kwargs):
        start_time = time()
        result = function(*args, **kwargs)
        end_time = time()
        measure = kwargs.get("measure")
        if measure:
            execution_time = end_time - start_time
            return result, execution_time
        return result
    return wrapper


@time_it
def aes(**kwargs):
    key = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    ])

    plaintext = bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encryptor.update(plaintext)
    encryptor.finalize()


@time_it
def md5(input, **kwargs):
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()


@time_it
def sha256(input, **kwargs):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()


@time_it
def sha512(input, **kwargs):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()


@time_it
def pbkdf2(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"12QIp/Kd"
    rounds = kwargs.get("rounds", 10000)
    return pbkdf2_sha256.hash(input, salt=salt, rounds=rounds)


@time_it
def argon2_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"0"*22
    rounds = kwargs.get("rounds", 12)              # time_cost
    memory_cost = kwargs.get("memory_cost", 2**10) # kibibytes
    parallelism = kwargs.get("rounds", 1)
    return argon2.using(
        salt=salt,
        rounds=rounds,
        memory_cost=memory_cost,
        parallelism=parallelism
    ).hash(input)


@time_it
def linux_hash_6(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = "12QIp/Kd"
    return sha512_crypt.hash(input, salt=salt, rounds=5000)


@time_it
def linux_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = kwargs.get("salt")
    rounds = kwargs.get("rounds", 5000)
    if salt:
        return sha512_crypt.hash(input, salt=salt, rounds=rounds)
    return sha512_crypt.hash(input, rounds=rounds)


@time_it
def scrypt_hash(input, **kwargs):
    salt = kwargs.get("salt", urandom(16))
    length = kwargs.get("length", 32)
    n = kwargs.get("n", 2**14)
    r = kwargs.get("r", 8)
    p = kwargs.get("p", 1)
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=n,
        r=r,
        p=p
    )
    hash = kdf.derive(input)
    return {
        "hash": hash,
        "salt": salt
    }


if __name__ == "__main__":
    ITERATIONS = 100
    password = b"super secret password"

    MEMORY_HARD_TESTS = []
    LOW_MEMORY_TESTS = []


    TESTS = [
        {
            "name": "AES",
            "service": lambda: aes(measure=True)
        },
        {
            "name": "HASH_MD5",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "HASH_SHA256",
            "service": lambda: sha512(password, measure=True)
        }
    ]

    table = PrettyTable()
    column_1 = "Function"
    column_2 = f"Avg. Time ({ITERATIONS} runs)"
    table.field_names = [column_1, column_2]
    table.align[column_1] = "l"
    table.align[column_2] = "c"
    table.sortby = column_2

    for test in TESTS:
        name = test.get("name")
        service = test.get("service")

        total_time = 0
        for iteration in range(0, ITERATIONS):
            print(f"Testing {name:>6} {iteration}/{ITERATIONS}", end="\r")
            _, execution_time = service()
            total_time += execution_time
        average_time = round(total_time/ITERATIONS, 6)
        table.add_row([name, average_time])
        print(f"{table}\n\n")


## 5. i 6. laboratorijska vjezba(grupa koja je kasnila)
# Vježba 5
U 5oj vježbi se analizira ranjivost lozinki prilikom offline i online pswd guessing attack.
-u offline napadu napadač nema interakciju sa serverom
-u online napadu ima s legitimnim serverom.
Ovdje govorimo o brute force napadima

ONLINE
vaki student ima podignut svoj Docker kontejner s vlastitom IP adredom i korisničkim imenom.
Ovdje ćemo koristiti alat HYDRA koji oponaša ssh kljinta u testira sve moguće lozinke.
Naredbe: hydra -l boric_dora -x 4:5:a 10:0.15.15 -V -t 1 ssh 
(koristimo riječnik) hydra boric_dora -P dictionary/g3/dictionary_online.txt 10.0.15.15 -V -t 4 ssh

Rezultat je pronalazak odgovarajuće lozinke kojom se možemo prijaviti na svoj virtualni stroj.

# Vježba 6
Prolazimo kroz onovne postupke upravljanja korisničkim računima na Linux OS s naglaskom na kontrolu pristupa datotekama, programima i
drugim resursima Linux sustava.

Kreiranjem korisnika/usera preko Linux Bash Shell korisnicima su dodjeljena prava različitih grupa.
tako ona mogu biti administratorska, ali i ne moraju.
Sudo grupa ima administratorska prava, predstavljaju admin te pomoću nje kreiramo dva korisnička računa.
sudo adduser alice3 i kasnije bob3

Pomoću security.txt kriramo datoteku preko koje ćemo testirati razine prava ova dva korisnika.

Naredbom getfalc provjeravama ta prava(citanje, pisanje,..) kao i dopuštenja definirana za pojedine direktorije

Trenutnom korisniku koji je vlasnik neke datoeke se prava mogu oduzeti koristeći skup naredbi chmod na sljedeći naćin:
chmod u-r security.txt

Ili dodjeliti prava tako da korisnika dodama u grupu korisnika npr. alice3 čiji članovui imaju mogućnost čitanja datoteke security.txt
usermod -aG <alice3> bob3

Kontrola pristupa korištenjem ACL. 
Ovim putem drugom korisniku dajemo pristup nekom direktoriju ako ga dodamo u  željene datoteke bez potrebe za dodavanjem u novu grupu.
setfacl -m u:bob3:r security.txt
    
A uklanjanje iz ACL je: setfacl -x u:bob3 security.txt

Sada možemo proučitikako Linux reagira na programe u izvođenju i kontroliranje pristupa njih.
Pokrenemo kao korisnik student koji je vlasni datoteke u kojoj se nalazi program koji pokreće skriptu koja će pokušati pritupiti datoteci security.txt i dobije poruku da je odbijen.
Korisnik bob3 nije vlasnik datoteke sa skriptom. ali njezinim pokretanjem joj može pristupiti.
