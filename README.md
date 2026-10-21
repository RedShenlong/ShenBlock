<h1 align="center">ShenBlock</h1>

<p align="center">
  Control e inventario de tu red local desde una interfaz de terminal moderna.
</p>

ShenBlock descubre los equipos conectados a tu red, los identifica (IP, MAC y
fabricante), te deja **bloquear** el acceso a internet de los que elijas y
**monitorizar en vivo** cuánto consume cada uno, todo desde una consola con un
diseño cuidado. Funciona emitiendo y gestionando tráfico ARP en la red local.

> ⚠️ **Úsalo solo en redes propias o con autorización expresa.** Es una
> herramienta educativa; actuar sobre redes de terceros puede ser ilegal.

## Características

- 🔎 **Escaneo** de la red local con barra de progreso, detectando todos los
  hosts activos.
- 🏷️ **Identificación** de cada equipo: dirección IP, MAC, fabricante y nombre.
  Detecta y avisa de las MAC aleatorias de los móviles.
- ⛔ **Bloqueo** del acceso a internet de los equipos que elijas, y liberación
  cuando quieras. Al salir, la red se restaura sola.
- 📊 **Monitor de consumo en vivo**, con el gasto de cada dispositivo (B/s,
  KB/s, MB/s…) y barras que se actualizan en tiempo real.
- 🎨 **Interfaz de terminal** con banner, colores y tablas claras.

## Requisitos

- Linux
- Python 3.10 o superior
- Privilegios de administrador (`sudo`), necesarios para el acceso a la red

## Instalación

```bash
git clone https://github.com/RedShenlong/ShenBlock.git
cd ShenBlock
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Después, lánzalo con privilegios (indicando la ruta del entorno, porque `sudo`
no hereda el `PATH` del entorno virtual):

```bash
sudo .venv/bin/shenblock
```

## Uso

Al arrancar, ShenBlock detecta automáticamente tu interfaz y tu red. Puedes
forzar otros valores con argumentos:

| Argumento        | Descripción                                             |
|------------------|---------------------------------------------------------|
| `--interface`    | interfaz de red a usar (p. ej. `eth0`)                  |
| `--network`      | red IPv4 en formato CIDR (p. ej. `192.168.1.0/24`)      |
| `--timeout`      | segundos de espera de respuestas al escanear            |
| `--no-hostname`  | no resolver nombres de los equipos                      |

Una vez dentro, se abre una consola propia con estos comandos:

| Comando             | Descripción                                             |
|---------------------|---------------------------------------------------------|
| `scan`              | descubre los equipos de la red                          |
| `hosts`             | muestra la tabla de equipos detectados                  |
| `info <n>`          | ficha detallada de un equipo por su número              |
| `block <sel>`       | bloquea equipos — `block 2,4` o `block all`             |
| `free <sel>`        | libera equipos — `free 2` o `free all`                  |
| `watch [sel]`       | monitor de consumo en vivo (`watch` para todos)         |
| `status`            | muestra qué equipos están bloqueados                    |
| `export <archivo>`  | guarda los equipos en `.json` o `.csv`                  |
| `help`              | muestra la ayuda                                        |
| `exit`              | restaura la red y cierra                                |

## Aviso legal

Este software se proporciona "tal cual", sin garantía de ningún tipo. Está
pensado con fines educativos y de administración de redes propias. El autor no
se hace responsable de ningún daño, pérdida de datos ni del uso indebido de la
herramienta. Al utilizarla, aceptas hacerlo únicamente en redes para las que
tengas autorización.

## Licencia

ShenBlock se distribuye bajo la licencia MIT. Consulta el archivo
[LICENSE](LICENSE) para más detalles.
