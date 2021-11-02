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