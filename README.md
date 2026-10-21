# ShenBlock

Inventario de red con interfaz de terminal (TUI) para **prácticas de laboratorio
autorizadas**. Descubre hosts IPv4 y sus direcciones MAC mediante solicitudes ARP
emitidas localmente, y los enriquece con fabricante (prefijo OUI) y nombre (DNS
inverso). **No** captura, intercepta ni lee tráfico de terceros.

> Proyecto de TFG. El módulo de acción implementa **envenenamiento ARP
> dirigido** (`shenblock/spoofer.py` + `shenblock/action.py`) para bloquear
> equipos en una red autorizada, con restauración automática de las tablas ARP
> al salir. El límite de ancho de banda (vía `tc/netem`) queda como extensión
> pendiente.
>
> ⚠️ **Uso autorizado únicamente.** `block` redirige y descarta el tráfico de
> los equipos objetivo. Ejecútelo solo en redes propias o con autorización
> expresa por escrito.

## Instalación

```bash
cd /home/d1ego/Projects/ShenBlock
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
sudo shenblock
```

`scapy` necesita privilegios de red para enviar y recibir respuestas ARP. Use
únicamente segmentos para los que tenga **autorización expresa**.

## Uso

```bash
sudo shenblock                 # autodetecta interfaz (prefiere wlan0) y red
sudo shenblock --interface eth0 --network 192.168.1.0/24
python -m shenblock            # equivalente sin el script instalado
```

Opciones útiles:

| Opción           | Descripción                                             |
|------------------|---------------------------------------------------------|
| `--interface`    | interfaz de red (p. ej. `eth0`)                         |
| `--network`      | red IPv4 en CIDR (p. ej. `192.168.1.0/24`)              |
| `--timeout`      | espera de respuestas ARP en segundos (por defecto 1.5)  |
| `--manuf RUTA`   | fichero OUI estilo *manuf* para ampliar los fabricantes |
| `--no-hostname`  | no resolver nombres por DNS inverso                     |

### Comandos de la consola

| Comando             | Acción                                                  |
|---------------------|---------------------------------------------------------|
| `scan` / `rescan`   | descubre equipos (con barra de progreso por fases)      |
| `hosts` / `ls`      | muestra la tabla del último escaneo                     |
| `info <n>`          | ficha detallada de un host                              |
| `block <sel>`       | **bloquea** objetivos (`block 2,4` o `block all`)       |
| `free <sel>`        | libera objetivos y restaura su ARP (`free all`)         |
| `watch [sel]`       | **monitor de consumo en vivo** (`watch all` = con MITM) |
| `status` / `st`     | muestra el bloqueo activo                               |
| `limit <sel>`       | límite de ancho de banda (pendiente, requiere `tc`)     |
| `export <archivo>`  | guarda los hosts en `.json` o `.csv`                    |
| `interfaces`        | lista las interfaces disponibles                        |
| `network <cidr>`    | muestra o cambia la red objetivo                        |
| `clear` / `help`    | limpia la pantalla / muestra la ayuda                   |
| `exit` / `q`        | libera todo, restaura la red y cierra                   |

`block` arranca un envenenamiento ARP en segundo plano (modelo persistente
estilo *evillimiter*): la consola sigue abierta y puede añadir o liberar
objetivos en caliente. El bloqueo desactiva el reenvío IP para descartar el
tráfico y lo restaura al terminar. La primera vez pide confirmación de
autorización.

### Identificación de equipos

La tabla `hosts` muestra el **fabricante** (resuelto con la base de datos OUI
que incluye Scapy, miles de prefijos, sin conexión), el **nombre** por DNS
inverso cuando el equipo lo publica y una columna de **estado** (`🔒 block` /
`✓ libre`). El gateway y el propio equipo se etiquetan automáticamente. El
consumo no aparece aquí (solo es fiable mientras se redirige el tráfico): se ve
en el monitor en vivo `watch`.

> **MAC privada:** los móviles modernos (iPhone, Android) usan una MAC
> aleatoria por privacidad. Esa dirección no pertenece a ningún fabricante, así
> que ShenBlock la marca como `(MAC privada)` en vez de inventar un fabricante.
> Es el comportamiento correcto, no un fallo. Si quieres ver el fabricante real
> de tu móvil, desactiva la "Dirección Wi-Fi privada" en sus ajustes de red.

### Monitor de consumo en vivo (`watch`)

`watch` abre un panel a pantalla completa que se actualiza en tiempo real con el
consumo por dispositivo (bytes/s) y una barra proporcional, ordenado de mayor a
menor gasto. `Ctrl+C` vuelve a la consola.

* `watch` o `watch all`: hace **MITM de todos** los equipos descubiertos
  (envenena con el reenvío IP activo, de modo que su conexión sigue funcionando
  pero pasa por esta máquina) para poder medir su consumo real.
* `watch 1,3`: lo mismo pero solo sobre esos equipos.

El panel se dibuja **en línea**, debajo de lo que ya tenías en la terminal, y se
refresca en el sitio sin borrar el historial. Al salir con `Ctrl+C` restaura
todo (ARP + reenvío IP).

> En una red conmutada solo se ve el tráfico que llega a tu tarjeta; por eso el
> consumo de *otros* equipos solo aparece cuando se redirige su tráfico (MITM),
> que es justo lo que hace `watch`.

## Arquitectura

```
shenblock/
├── __init__.py     versión del paquete
├── __main__.py     python -m shenblock
├── theme.py        paleta y consola de Rich
├── models.py       Device y SessionPlan (inmutables)
├── oui.py          fabricante por prefijo OUI (offline)
├── scanner.py      descubrimiento ARP, gateway y resolución de MAC
├── spoofer.py      ARPSpoofer: envenenamiento ARP en segundo plano
├── monitor.py      BandwidthMonitor: consumo por dispositivo
├── system.py       control de reenvío IPv4 (ip_forward)
├── action.py       LaboratoryAction: orquesta spoofer + reenvío
├── ui.py           banner, tablas, dashboard y barra de progreso
└── cli.py          consola interactiva y punto de entrada
```

### El módulo de acción

`LaboratoryAction` (en `shenblock/action.py`) coordina el `ARPSpoofer` y el
reenvío IP, y expone el contrato que usa la consola:

```python
class LaboratoryAction:
    def run(self, plan: SessionPlan) -> None: ...   # arranca desde un plan
    def block(self, devices) -> int: ...            # añade objetivos (en caliente)
    def free(self, devices) -> int: ...             # libera y restaura
    def refresh(self) -> str | None: ...            # estado para la TUI
    def stop(self) -> None: ...                     # restaura ARP + ip_forward
```

**Qué falta (extensión del TFG):** el límite de ancho de banda. Con el tráfico
ya reenviado por esta máquina, el siguiente paso es modelar la ruta con
`tc`/`netem` (p. ej. `tc qdisc add dev <iface> root netem rate <X>`) en lugar de
descartar el tráfico. Cread un modo `drop_traffic=False` en `LaboratoryAction`
que active el reenvío y aplique la disciplina de cola.

## Pruebas

```bash
pip install pytest
pytest
```

Las pruebas **no envían paquetes reales**: parchean `scapy.send` y el control de
reenvío, de modo que verifican la construcción de paquetes y la lógica de
bloqueo/restauración sin tocar la red.

## Aviso legal

Herramienta educativa para redes propias o con autorización explícita por
escrito. El uso contra redes de terceros puede ser ilegal. Los autores no se
responsabilizan de un uso indebido.
