# THM-TakeOver
**Enumeración técnica (SSL) y análisis de protocolos (HTTP)**
<br>
<br>
<br>
**NMAP**

```bash
nmap -p- -sC -sV -sS --open --min-rate 5000 -n -Pn 10.82.129.249 -oN takeover_scan.txt
```
```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0f:0b:b3:26:b0:50:1e:24:00:4c:2e:ea:42:22:e7:0e (RSA)
|   256 db:37:47:04:d9:fa:22:e1:07:10:7f:23:48:d5:9f:b7 (ECDSA)
|_  256 c5:0f:93:c1:de:0a:63:b0:c8:5f:46:a9:cf:9c:14:ff (ED25519)
80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://futurevera.thm/
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: FutureVera
| ssl-cert: Subject: commonName=futurevera.thm/organizationName=Futurevera/stateOrProvinceName=Oregon/countryName=US
| Not valid before: 2022-03-13T10:05:19
|_Not valid after:  2023-03-13T10:05:19
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**whatweb**

```bash
 whatweb http://futurevera.thm 
```
<br>

```
http://futurevera.thm [302 Found] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.82.129.249], RedirectLocation[https://futurevera.thm/]
https://futurevera.thm/ [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.82.129.249], Script, Title[FutureVera]
```
<br>

Metemos el dominio en ```/etc/hosts```
<br>

```bash
echo "10.82.129.249 https://futurevera.thm/" | sudo tee -a /etc/hosts 

```

## **Encontrando subodminios**

```bash
wfuzz --hl=0 --hc=404 -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.futurevera.thm" -u 10.82.129.249

```

```bash
200        1 L      9 W        69 Ch       "portal"
200        1 L      9 W        70 Ch       "payroll"

```

Estos dos subdominios nos daban el mismo Content-Length(**4605**) Esto saignifica que estan devolviendo el mismo tamaño de pagina y eso es bastante raro

El concepto del **Content-Length** (o tamaño de la respuesta) es uno de los filtros más potentes en la fase de enumeración, y en este CTF fue exactamente lo que nos permitió separar la "basura" de la información real.


---

### ¿Qué es el Content-Length?

Cuando haces una petición a un servidor, este te responde con una cabecera HTTP llamada `Content-Length`. Este valor indica el **tamaño exacto en bytes** del cuerpo de la página web (el código HTML, texto, etc.).

- Si una página te dice "Hola", su length será pequeño (ej. 4 bytes).
- Si una página tiene un diseño complejo, su length será grande (ej. 50,000 bytes).

### El problema de este CTF: Los "Falsos Positivos"

En el servidor de **FutureVera**, el administrador configuró Apache de tal manera que cualquier subdominio que **no estuviera definido** (o que estuviera vacío) redirigía a una página por defecto.

Cuando lanzamos el primer `wfuzz` o `ffuf`, ocurrió esto:

- `portal.futurevera.thm` -> **200 OK** (Tamaño: **4605**)
- `payroll.futurevera.thm` -> **200 OK** (Tamaño: **4605**)
- `inventado.futurevera.thm` -> **200 OK** (Tamaño: **4605**)

Como todos devolvían un código `200 OK`, las herramientas de ataque pensaban que todos eran válidos. Sin el filtro de tamaño habriamos tenido que revisar manualmente cientos de resultados idénticos.

Metemos estos subdominios que hemos encontrado tambien en ```/etc/hots```

## **Encontrando directorios en futurevera.thm**

```bash
gobuster dir -u http://futurevera.thm -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php,txt,html
```
<br>

```
/index.php            (Status: 302) [Size: 0] [--> https://futurevera.thm/]
```

Parece que no da nada interesante asique vamos a hacer una enumeración de directorios mas exhaustiva:

```bash
wfuzz -c --hc 404 --hh 4605 -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.futurevera.thm" -u https://10.82.129.249 -t 50

```
<br>
<br>
<img width="621" height="117" alt="takeover" src="https://github.com/user-attachments/assets/f3e3250f-f3cb-437e-8212-fd5c28f5d64a" />
<br>
<br>


### Explicación del comando:

**`wfuzz -c`**

- **Significado:** Activa el modo **Color**.
- Parece una tontería, pero cuando ves miles de líneas, el ojo humano detecta mucho mejor un cambio de color en los códigos `200` o `404`.

**`-hc 404`** 

- 
- Le dice a Wfuzz: "No me enseñes las páginas que no existen". Esto limpia la pantalla de basura.

**`-hh 4605` (ESTA ES LA CLAVE)**

- **Significado:** Hide Chars 4605.
- Al poner `-hh 4605`, le dices: "Ignora todo lo que mida 4605". Como `support` y `blog` miden algo distinto (porque tienen contenido real), **son los únicos que logran "saltar" el filtro y aparecer en tu pantalla.**

**`w /.../subdomains-top1million-5000.txt`**

- **Significado:** Wordlist (Diccionario).
- Es nuestra "munición". Estamos probando los 5000 nombres más comunes de subdominios.

**`H "Host: FUZZ.futurevera.thm"`**

- **Significado:** Inyecta la palabra del diccionario en la cabecera **Host**.
- Esto se llama **VHost Fuzzing**. Como la IP es la misma para todos, el servidor Apache solo sabe qué página enseñarte si nosotros le decimos el nombre específico en esta cabecera.

**`https://10.82.129.249` (LA SEGUNDA CLAVE)**

- Nuestro comando anterior usaba `http`. En esta máquina, el administrador configuró los subdominios interesantes (`support`, `blog`) **solo para el puerto 443 (SSL)**. Si les preguntas por el puerto 80 (HTTP), el servidor se hace el tonto y nos manda a la página genérica de 4605 caracteres.

**`t 50`**

- **Significado:** Threads (Hilos).
-Simplemente hace que el ataque sea 50 veces más rápido que si probara los nombres uno por uno.

Por eso en el nuevo comando, en cuanto ```Wfuzz``` encontró `support` y vio que medía (por ejemplo) `1500` caracteres, nos dejo verlo.

---


Volvemos a meterlo en el ```etc/hosts```

<br>
<br>
<img width="1896" height="843" alt="pagina1" src="https://github.com/user-attachments/assets/2e857b0f-7b8f-4ba5-9674-b636b0fdc426" />
<img width="1902" height="1039" alt="pagina2" src="https://github.com/user-attachments/assets/eeecd1f6-495c-41a8-b470-36f8c9ef9b2c" />
<br>
<br>

A simple vista no nos aparece demasiado salvo un posible usuario asique vamos a enumerar directorios justo de estos subdominios

## **Enumerando nuevos subdominios**

```bash
gobuster dir -u https://blog.futurevera.thm -w /usr/share/wordlists/dirb/common.txt -k -x php,txt,html,bak
gobuster dir -u https://support.futurevera.thm -w /usr/share/wordlists/dirb/common.txt -k -x php,txt,html,bak
```

Tampoco da nada relevante asique pasamos al comando definitivo:

### Enumerando con Openssl

```bash
openssl s_client -connect 10.82.129.249:443 -servername support.futurevera.thm < /dev/null 2>/dev/null | openssl x509 -text | grep -i "DNS"
```

<br>
<br>
<img width="938" height="90" alt="openssl" src="https://github.com/user-attachments/assets/fb2b5e0c-3ad0-4b5e-a620-1b8436e3f22a" />
<br>
<br>

Ese subdominio largo y extraño (`secrethelpdesk934752.support.futurevera.thm`) es un **subdominio de tercer nivel**. Ningún diccionario de `wfuzz` o `gobuster` normal lo habría encontrado porque tiene un número aleatorio al final. Solo el certificado SSL podía revelarlo.

Esto es muy común en empresas reales. Crean un subdominio secreto para que solo lo usen los empleados, pero se olvidan de que el **Certificado SSL es público**. Al mirar el certificado, cualquier atacante puede ver todos los nombres que ese certificado protege.

Intentamos todo tipo de enumeraciones de este nuevo subdominio pero no nos apareció nada revelador  pero al final entrando simplemente en el **puerto 80** ya me dio la flag.


<br>
<br>
<img width="1492" height="854" alt="panel flag" src="https://github.com/user-attachments/assets/e379e2a7-57c9-4da2-be89-0f0790f5e188" />
<br>
<br>

Desglosando la explotacion **Subdomain Takeover** de este CTF:

1. El subdominio largo estaba configurado para apuntar a una URL de Amazon: `flag{...}.s3-website-us-west-3.amazonaws.com`.
2. Como ese sitio de Amazon probablemente no existe o no está configurado, el navegador nos muestra el error de "Servidor no encontrado".
3. **Pero**, como el administrador fue tan amable (o descuidado) de poner la **flag directamente en el nombre del subdominio de destino**, la hemos podido leer sin ni siquiera llegar a cargar la página.

### ¿Por qué funcionó con el puerto 80?

Normalmente, los servidores web tienen configuraciones distintas para HTTP (80) y HTTPS (443). Es muy probable que:

- En el **puerto 443**, el servidor simplemente nos soltaba la página por defecto configurada (el tamaño 4605 que veíamos).
- En el **puerto 80**, el servidor tenía activa la **redirección (301/302 Redirect)** hacia Amazon. Al intentar seguir esa redirección, nuestro navegador nos mostró la URL de destino en la barra de direcciones y en el mensaje de error, revelando la flag.

---

