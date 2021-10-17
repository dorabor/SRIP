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

Međutm pokretanjem tcpdump u evil station kontjeneru prethodne navedene stavke i informacije o komunikaciji dobivamo,