---
theme: default
---

# PSA-Praktikum Blatt 8

LDAP

<div class="absolute bottom-10">
  <span class="font-700">
    Team09
  </span>
</div>

---

# Installation

Grundlegende Installation des default ldap servers für Ubuntu: slapd

```bash
sudo apt install slapd ldap-utils
```

Mittels des folgenden Befehls kann man dann seine Base Domäne/ Präfix für den DIT (Directory Information Tree) über eine rudimentäre UI eingeben und ein admin Passwort festlegen (hier bei uns PWD: admin123)

```bash
sudo dpkg-reconfigure slapd
```

---

# TLS

Nutzen des certtools für linux. Also Zuerst das certtool installieren

```bash
sudo apt install gnutls-bin ssl-cert
```

---

Erstellen einer Template Datei für die CA unter `/etc/ssl/ca.info/` mit folgendem Inhalt:

```bash
cn = PSA TUM
ca
cert_signing_key
expiration_days = 3650
```

Dann erzeugen des selbstsignierten CA Zertifikat mithilfe des certtools:

```bash
sudo certtool --generate-self-signed \
--load-privkey /etc/ssl/private/mycakey.pem \
--template /etc/ssl/ca.info \
--outfile /usr/local/share/ca-certificates/mycacert.crt
```

Zum Abschluss führt man noch folgenden Befehl aus der das neue CA Zertifikat zur Liste an vertrauenswürdigen CAs hinzuzufügen:

```bash
update-ca-certificates
```

Um dem LDAP Server noch mitzuteilen das neu erzeugte Zertifikat zu nutzen muss man der config Datenbank folgende .ldif Datei zum verarbeiten geben:

```bash
dn: cn=config
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ssl/certs/mycacert.pem

- add: olcTLSCertificateFile
  olcTLSCertificateFile: /etc/ldap/ldap01_slapd_cert.pem
- add: olcTLSCertificateKeyFile
  olcTLSCertificateKeyFile: /etc/ldap/ldap01_slapd_key.pem

```

Anschließend wird dieses File mittels folgenden `ldapmodify` Befehl in den LDAP Server eingespeist:

```bash
sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f certinfo.ldif
```

---

## Testen

Zum testen der TLS Verbindung kann man dann folgenden Befehl mit dessen Output betrachten:

```bash
root@vmpsateam09-05:~# openssl s_client -connect 192.168.9.9:389 -starttls ldap
CONNECTED(00000003)
Cant use SSL_get_servername
depth=1 CN = PSA TUM
verify return:1
depth=0 CN = vmpsateam09-09.psa-team09.in.tum.de, O = PSA TUM
verify return:1

---

Certificate chain
0 s:CN = vmpsateam09-09.psa-team09.in.tum.de, O = PSA TUM
i:CN = PSA TUM
1 s:CN = PSA TUM
i:CN = PSA TUM

---

Server certificate
-----BEGIN CERTIFICATE-----
MIIEVjCCAj6gAwIBAgIUQUhzMmOO4918rt8WrKSw0sQfbaIwDQYJKoZIhvcNAQEM
BQAwEjEQMA4GA1UEAxMHUFNBIFRVTTAeFw0yMTEyMjAyMDI2MzZaFw0yMjEyMjAy
MDI2MzZaMEAxLDAqBgNVBAMTI3ZtcHNhdGVhbTA5LTA5LnBzYS10ZWFtMDkuaW4u
dHVtLmRlMRAwDgYDVQQKEwdQU0EgVFVNMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAv19oGTfo/dgRRgYyBt/P6jIg35q56X5Tz8akQq9K5uxYhfyN5WnE
Yjekcr4V/XECOnyA4tm7Lu9G57XBf3v9W28WpQgiLwKIza6gNlxH9G58jcNBKpEM
ojlLwgeLJ16NVzfDQVe3MRKzJVoZU+2E+ANHH4NWctTaQmi7ySOOZfInjC9Piv69
AgKXM09J6D1/IY6FGEQt/TtPo2JMkkYDmvmW2qCuQkYhRPske2GzsFIgg500W0+h
VnpkVcYuXvE9VdS1PcgBx0Apx80PXRo8DzMJRRL+x89yPDby5TWVHRBQ3ZcHpbE0
31yk+m4oRJi8aIKbLr+ccIggNZXtm5NlaQIDAQABo3YwdDAMBgNVHRMBAf8EAjAA
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdDwEB/wQFAwMHoAAwHQYDVR0OBBYE
FGChF0CM2rm3I3v1iUITWCi0s45OMB8GA1UdIwQYMBaAFA2QC/AaKpnLRIFSCWiU
CRDqdg1CMA0GCSqGSIb3DQEBDAUAA4ICAQAOa2yduhCGLTvFLRo7aPNu9rw+TZuB
teBgzV0opbuYE/XgQfH/xLTB3yXtk4SWIGI9EMNKTyKqKc2kGQXM53q0i+l9cYj3
t8RXn94Wyo8/et3gIxN+ODsfBFJXCZE0EL6wvM+udoRUF/1q0yTApYxvWSmgMFkX
jLE5c2hcy83/xW4vnJ+p52HmRImVUExzf9DlWBeAcIeqg099tFpxPncSK8RJiTOd
AuX5mBtUko5A1/X8iLGPMvf7GzFsl5OE53FVMK7LseoPGzdJ6uqjt545LluHAEyq
d5pZTkjbIc7Q81MahwWP8GVmv38cIUmedq3O0ApYJ7iw6RVZDRWB2hOhII+wAln2
WN8it8SDY3N0r2FLNhd4BYPHME/X5y6iMvpgjfZRHop1Gqv9i7lETiHvshuEBwsq
cRJdcc8VqMCDv+EkRc1dPUP+wqFb7M5KSYmLkjLrMF1NhFsqLdkurSXjrJzXxEoG
NGcB+pcvoMRj9ycT7T4gPP/wUhoExLlnA/o8vy8pABwgT74fA7GiIjaqBhQkTD3a
W9IvaIPR/GRO/EUFNwO9FDWKAYtBnn0XgECE0jg6GpA5+cOqQvE/vQTn3oc8SHgD
E/iAJWxOWbQ4b5+9hFlafUDs06JJubYLEZTyV4KsFFUEiT8d421n1vRHuUWmpNRe
bVlZ5y+dCk3BZQ==
-----END CERTIFICATE-----
subject=CN = vmpsateam09-09.psa-team09.in.tum.de, O = PSA TUM

issuer=CN = PSA TUM

---

No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits

---

SSL handshake has read 2962 bytes and written 394 bytes
Verification: OK

---

New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 2048 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
```

---

# Daten hinzufügen

Um Dateneinträge unserem LDAP Server hinzuzufügen bzw. diese zu ändern werden folgende Befehle benötigt,
welche wir alle aus einem sogenannten ldif File lesen:

```bash
ldapadd -x -D "cn=admin,dc=team09,dc=psa,dc=in,dc=tum,dc=de" -f file.ldif -W
ldapmodify -x -D "cn=admin,dc=team09,dc=psa,dc=in,dc=tum,dc=de" -f file.ldif -W
```

---

## Object Units (OU) allgemein anlegen

```bash
dn: ou=users,dc=team09,dc=psa,dc=in,dc=tum,dc=de #distinguished_name eintrag
objectclass: top #classes with attributes
objectclass: organizationalUnit #classes with attributes
ou: users #concrete attribute with value

dn: ou=groups,dc=team09,dc=psa,dc=in,dc=tum,dc=de
objectclass: top
objectclass: organizationalUnit
ou: groups

dn: ou=computers,dc=team09,dc=psa,dc=in,dc=tum,dc=de
objectclass: top
objectclass: organizationalUnit
ou: computers

dn: ou=psaou,dc=team09,dc=psa,dc=in,dc=tum,dc=de
objectclass: top
objectclass: organizationalUnit
ou: psaou

```

---

## OU users

Gruppe für alle Nutzerkennungen der Mitglieder des Praktikums.

```bash
dn: uid=ge49vaz,ou=users,dc=team09,dc=psa,dc=in,dc=tum,dc=de
objectClass: posixAccount
objectClass: shadowAccount
objectClass: inetOrgPerson
cn: Simon
sn: Heinrich
uid: ge49vaz
uidNumber: 1092
gidNumber: 1090
homeDirectory: /home/ge49vaz
loginShell: /bin/bash
gecos: Simon Heinrich
userPassword: XXXXXXX
```

---

## OU groups

Gruppe für alle Groups die mit Teams aus dem Praktikum assoziiert werden.

```bash
dn: ou=users,dc=team09,dc=psa,dc=in,dc=tum,dc=de
objectclass: top
objectclass: organizationalUnit
ou: users
```

---

## OU computers

Gruppe für alle unsere VMs und deren Kennung zur Abfrage von Nutzerkennungen (Grund siehe LDAP-Zugriffsrechte)

```bash
dn: cn=vm05,ou=computers,dc=team09,dc=psa,dc=in,dc=tum,dc=de
objectClass: top
objectClass: person
cn: vm05
sn: VM 05 - Test Server
userPassword: XXXXXXX
```

---

## OU psaou

Gruppe für alle Nutzerkennung die wir aus dem CSV File eingelesen. Hier wird auch unser selbsterzeugtes Schema psaPerson genutzt (mehr dazu unter LDAP-Eigenes Schema erzeugen)

```bash
dn: Matrikelnummer=1622888953,ou=psaou,dc=team09,dc=psa,dc=in,dc=tum,dc=de
objectClass: posixAccount
objectClass: shadowAccount
objectClass: inetOrgPerson
objectClass: psaPerson
uid: 1622888953
gidNumber: 10001
uidNumber: 8021
cn: Clarissa
sn: Attenberger
homeDirectory: /home/Attenberger
Nachname: Attenberger
Vorname: Clarissa
Geschlecht: m
Geburtsdatum: 02.01.88
Geburtsort: Pegnitz
Nationalitaet: Deutschland
Strasse: Ilinden Street nr. 145
PLZ: 53604
Ort: Muenchen DE
Telefon: 0455/67742938
Matrikelnummer: 1622888953
```

---

# Eigenes Schema erzeugen

Um die Daten aus der CSV Datei übersichtlich und mit den angegeben Attributen im LDAP Server abspeichern zu können, haben wir ein eigenes Schema psaPerson angelegt. Ein Schema entspricht konzeptionell einer Objekt Klasse mit Attributen. Man legt fest welche Attribute welchen Typ haben und welche Attribute beim Nutzen des Schemas angegeben werden müssen und welche Attribute optional sind. Wir haben den Nachnamen und die Matrikelnummer als notwendige Attribute festgelegt, wobei die Matrikelnummer den Unique Identifier für den Eintrag einer psaPerson angibt.

Als erstes legt man ein new.schema Datei an, die eine spezielle Syntax hat und in unserem Fall wie folgt aufgebaut ist:

```bash
objectidentifier psaSchema 1.3.6.1.4.1.A.B # Unique ObjectIdentifier OID for the scheme --> A and B arbitary numbers for unique idntification
objectidentifier psaAttrs psaSchema:X # OID for all Attributes --> OID from scheme + ".X"
objectidentifier psaOCs psaSchema:Y # OID for all ObjectClass definitions --> OID from scheme + ".Y"

attributetype ( psaAttrs:1 # new attributetype with OID psaAttrs + ".1"
NAME 'Nachname' # new name for the attributetype
DESC 'PSA Nachname Identifier' # new description for the attributetype
EQUALITY caseIgnoreMatch # behavior for rules with equal name --> here: ignore
SUBSTR caseIgnoreSubstringsMatch # behavior for rules with similar name(substring) --> here: ignore
SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32} ) # attribute Type: String{field with 32 characters}
attributetype ( psaAttrs:2
NAME 'Vorname'
DESC 'PSA Vorname Identifier'
EQUALITY caseIgnoreMatch
SUBSTR caseIgnoreSubstringsMatch
SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32} )

#

#

#

# More Attributes here

#

#

#

objectClass ( psaOCs:1 # new objectClass with OID psaOCs + ".1"
NAME 'psaPerson' # new name for the objectClass
DESC 'Describe a PSA Person' # new description for the objectClass
SUP ( top ) AUXILIARY # Superior objectClass (here:top) ; type of objectClass here(AUXILIARY)
MUST ( Matrikelnummer $ Name ) # attributes that have to be filled
MAY ( Vorname $ Geschlecht $ Geburtsdatum $
Geburtsort $ Nationalitaet $ Strasse $ PLZ $ Ort $ Telefon ) ) # attributes that can be filled
```

- Sobald diese new.schema Datei fertig erzeugt man sich ein neues tmp Directory und ein neues tmp.conf file:

```bash
mkdir tmp
touch tmp.conf
```

- Inhalt der tmp.conf Datei:

```bash
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/nis.schema
include /etc/ldap/schema/inetorgperson.schema
include $path to new.schema file$
```

- Mittels folgendem Befehl wird dann eine Test Config Umgebung des LDAP Servers erzeugt, was unsere new.schema Datei in ein ldif Format umbaut was der LDAP Server lesen kann:

```bash
slaptest -f /$path$/test.conf -F /$path$/schema/tmp
```

- Anschließend kann man diese Datei aus dem tmp Ordner zum Verzeichnis des LDAP Servers kopieren und den Server neustarten. Dann steht das Schema zur Verfügung.

```bash
cp /$path$/tmp/cn=config/cn=schema/cn={4}new.ldif /etc/ldap/slapd.d/cn=config/cn=schema/
systemctl restart slapd.service
```

- Anmerkung: Dieses so erzeugte Schema ist zum Zweck der im Aufgabenblatt geforderten einfügen der CSV erzeugt worden und ist deshalb kein eigenständiges Strukturelles Schema weil wir wie man oben gesehen hat (LDAP-Daten hinzufügen - OU psaou) dieses Schema in Kombination mit anderen strukturellen Schemata (inetOrgPerson,posixAccount,shadowAccount) verwenden. Es dient allein zu Organisation der Daten. Das liegt am Eintrag AUXILARY im .schema file. Bei diesem Eintrag gibt es noch mehr Optionen was aber für unsere Zweck nicht notwendig wahr.

---

# Einlesen der CSV Datei

1. CSV Datei einlesen
2. Ausschreiben im richtigen Format in eine `ldif` datei
3. X.509 Zertifikat hinzufügen

Zuerst schauen wir uns das Format der CSV Datei an:

```bash
head -n 1 testdata/benutzerdaten.csv
"Name","Vorname","Geschlecht","Geburtsdatum","Geburtsort","Nationalit�t","Stra�e","PLZ","Ort","Telefon","Matrikelnummer"
```

---

```python {all|9|17-31}
class LdifEntry:
    matrNr = 0
    uidNum = '' 
    firstName = ''
    lastName = ''
    attributes = {}
    userCertificatePath = ''

    def __init__(self, matrNr, uidNum, firstName, lastName, attrNames, row):
        # Initialisations...
        self.userCertificatePath = CERTIFICATES + matrNr + ".der"

        # Replace Name attribute name with Nachname
        attrNames = ['Nachname' if item == 'Name' else item for item in attrNames]
        self.attributes = dict(zip(attrNames, row))

    def __str__(self):
        entry = textwrap.dedent("""\
            dn: Matrikelnummer=%s,ou=psaou,dc=team09,dc=psa,dc=in,dc=tum,dc=de
            objectClass: posixAccount
            objectClass: shadowAccount
            objectClass: inetOrgPerson
            objectClass: psaPerson
            uid: %s
            gidNumber: 10001
            uidNumber: %s
            cn: %s
            sn: %s
            homeDirectory: /home/%s
            usercertificate;binary:<file://%s
        """%(self.matrNr, self.matrNr, self.uidNum,...))

        for attrName, value in self.attributes.items():
            entry = entry + attrName + ': ' + value + '\n'

        return entry
```

---

```python {all|1-8|9-15|16-21|23-37}
def main():
    with open(CSV_FILE, newline='', encoding='latin-1') as f:
        reader = csv.reader(f)

        uidNum = 8000
        firstRow = True

        for row in reader:
            # Replace german umlaute
            row = list(map(lambda s: s.replace(u'ä', 'ae')
                                      .replace(u'ö', 'oe')
                                      .replace(u'ü', 'ue')
                                      .replace(u'ß', 'ss')
                                      , row))

            if (firstRow):
                attributes = row
                matrNrIndex = row.index("Matrikelnummer")
                firstNameIndex = row.index("Vorname")
                lastNameIndex = row.index("Name")
                firstRow = False

            else:
                entry = LdifEntry(
                            row[matrNrIndex], 
                            uidNum,
                            row[firstNameIndex], 
                            row[lastNameIndex], 
                            attributes,
                            row)

                uidNum = uidNum + 1

                fileName = LDAP_DATA_FOLDER + getattr(entry, 'lastName') + '.ldif'

                file = open(fileName, 'x');
                file.write(str(entry))
```

---

# DAP - Zugriffsrechte

Laut Aufgabenstellung soll durch einen anonymous bind (Zugriff auf den Server ohne Authentifizierung) lediglich die Benutzerkennung (bei uns uid Attribut) der jeweiligen Einträge angezeigt werden. Dafür müssen die Zugriffsrechte angepasst werden. Der OpenLDAP Server auf Ubuntu wird durch den cn=config tree definiert, also ein eigener Eintrag im LDAP Server. Hier gibt es das Attribut olcAccess was die Zugriffsrechte regelt.

- Anzeigen der aktuellen Zugriffsrechte mit einer ldapsearch auf das **olcAccess **Attribut:

```bash
root@vmpsateam09-09:~# ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config 'olcDatabase={1}mdb'
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0

# extended LDIF

#

# LDAPv3

# base <cn=config> with scope subtree

# filter: olcDatabase={1}mdb

# requesting: ALL

#

# {1}mdb, config

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: {1}mdb
olcDbDirectory: /var/lib/ldap
olcSuffix: dc=team09,dc=psa,dc=in,dc=tum,dc=de
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by _ none
olcAccess: {1}to attrs=shadowLastChange by self write by users read
olcAccess: {2}to attrs=uid,entry by anonymous read by _ break
olcAccess: {3}to \* by self write by anonymous none by users read
olcLastMod: TRUE
olcRootDN: cn=admin,dc=team09,dc=psa,dc=in,dc=tum,dc=de
olcRootPW: {SSHA}Fm+IDJ3HPqNC6Rwzo5fxguYiP3B8FtiE
olcDbCheckpoint: 512 30
olcDbIndex: objectClass eq
olcDbIndex: cn,uid eq
olcDbIndex: uidNumber,gidNumber eq
olcDbIndex: member,memberUid eq
olcDbMaxSize: 1073741824

# search result

search: 2
result: 0 Success

# numResponses: 2

# numEntries: 1

```

- Die ersten beiden Einträge (olcAccess: {0} + {1}) sind default einträge, die Passwort Authentifizierung regeln. Um nun den anonymous bind einzuschränken haben wir die anderen beiden Regeln angelegt
  ** olcAccess: {2} -> Regelt den Zugriff auf die Benutzerkennung(uid) und gibt diese der Gruppe anonymous frei. Es steht noch bei attributes der Eintrag entry dabei. Bei diesem handelt es sich um ein Pseudonym Attribut was beim read Zugriff auf alle Attribute gebrauucht wird. Wichtig ist zuletzt das alle anderen Accessgruppen (\*) noch aus dieser Regel break dürfen, da beim LDAP Access sobald eine Regel gematcht wird nicht automatisch die anderen Regeln abgeglichen werden.
  ** olcAccess: {3} -> Regelt dann den Zugriff auf alle anderen Einträge in der LDAP Datenbank(\*). Wobei der anonymous ausdrücklich keine Zugang mehr hat und die Gruppe users (authentifizierte binds) alles lesen darf
- Diese regeln werden wie alle Einträge im LDAP Server mittels einer ldif Datei angepasst:

```bash
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword
by self write
by anonymous auth
by \* none

- add: olcAccess
  olcAccess: {1}to attrs=shadowLastChange
  by self write
  by users read
- add: olcAccess
  olcAccess: {2}to attrs=uid,entry
  by anonymous read
  by \* break
- add: olcAccess
  olcAccess: {3}to \*
  by self write
  by anonymous none
  by users read
```

- Diese ldif Datei kann mittels folgendem Befehl eingespielt werden:

```bash
ldapmodify -H ldapi:/// -f access.ldif -D "cn=admin,dc=team09,dc=psa,dc=in,dc=tum,dc=de" -W
```

- Zum testen kann man dann auf einer Nutzer VM folgenden Befehl ausführen welcher über einen anonymous bind einen Such abfrage startet und man sollte nur noch die uid finden egal welcehn filter man verwendet:

```bash
ldapsearch -x -h vm09.psa-team09.in.tum.de -b dc=team09,dc=psa,dc=in,dc=tum,dc=de "(uid=\*)"
```

- Konsequenzen: Der Default Weg über den der sssd Service die authentifizierung über den LDAP Server abwickelt ist ein anonymous bind. Wir haben das so geregelt dass jede Nutzer VM einen eigenen Account im LDAP Server in der OU computers erhält und diser dann im sssd Service eingtragen wird (siehe SSSD)

---

# Erzeugen eines X.509 Zertifikats/ Hinzufügen zu LDAP-Einträgen

TODO

---

# SSSD - Installation/Konfiguration

Der System Security Services Daemon ist eine Sammlung von Diensten, die zur Authentifizierung und Sicherheit dienen. In unserem Fall übernimmt der sssd die Authentifizierung durch unseren LDAP Server.

Installation:

```bash
sudo apt install sssd-ldap ldap-utils
```

Bei dieser Installation werden folgende wichtige Dateien angepasst damit der sssd Service bei der Authentifizierung eines Nutzers auch befragt wird TODO bsp pam_sss:

```bash
/etc/pam.d/\*
/etc/nswitch.conf
```

```bash
[sssd]
config_file_version = 2
domains = psa-team09.in.tum.de

[domain/psa-team09.in.tum.de]
id_provider = ldap # use LDAP for id resolution
auth_provider = ldap # use LDAP for authentification
ldap_uri = ldap://vmpsateam09-09.psa-team09.in.tum.de # verbindung zum ldap-server
cache_credentials = True
ldap_search_base = dc=team09,dc=psa,dc=in,dc=tum,dc=de # base domain des ldap-servers
ldap_id_use_start_tls = true # use TLS connection
ldap_default_bind_dn = cn=vm05,ou=computers,dc=team09,dc=psa,dc=in,dc=tum,dc=de # account für bind an den ldap server
ldap_default_authtok_type = password # art der authentifikation am ldap-server
ldap_default_authtok = XXXXXXXXX # passwort für ldap-server account
ldap_tls_reqcert = allow
```

Hier werden die Art der Authentifizierung (ldap) und die Account Daten des jeweiligen ldap Accounts für die entsprechende VM angegeben außerdem, dass wir über TLS kommunizieren wollen. Man kann die ganzen Abfragen auch über einen anonymous bind zum LDAP Server machen aber das würde dann der Aufgabenstellung widersprechen in der ein anonymous bind nur die uid anzeigen lassen soll (Mehr dazu in #Zugriffsrechte)

Starten des sssd Services:

```bash
sudo systemctl start sssd.service
```

Aktivieren der automatischen Erzeugung von home directorys - nutzen des im LDAP server hinterlegten home Verzeichnis-Pfad:

```bash
sudo pam-auth-update --enable mkhomedir
```

Dann sollte man die Verbindung zum LDAP-Server noch testen. Mit folgenden Befehl kann man einen anonymous bind (bind ohne Nutzer Kennung) ausführen und bekommt anonymous zurück:

```bash
root@vmpsateam09-04:~# ldapwhoami -x -ZZ -h vmpsateam09-09.psa-team09.in.tum.de
anonymous
```

Der letzte Schritt ist dann das löschen der lokalen Nutzern aus den Dateien damit nur noch Daten aus dem LDAP Server genutzt werden:

```bash
userdel nutzerkennung # ohne löschen des homeverzeichnisses

# oder manuell aus den beiden lokalen dateien löschen

#/etc/passwd
#/etc/shadow
```

Zum Überprüfen eignen sich folgende Befehle:

```bash
id -a userkennung
su userkennung
passwd # als user
```

---

# Anmerkungen

TODO - sss cache + slapd debug
