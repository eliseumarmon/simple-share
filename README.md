# Simple Share

Comparte una carpeta con otros dispositivos de tu red local desde el navegador. Solo necesitas Python 3.10 o posterior; no hay paquetes que instalar.

Permite subir y descargar archivos, crear carpetas, renombrar, mover, copiar y eliminar elementos. También admite selección múltiple y evita sobrescribir nombres existentes añadiendo sufijos como `foto (1).jpg`.

## Inicio rápido

```bash
python3 simple_share.py
```

En Windows puedes usar `python simple_share.py` o `py simple_share.py`. Sin indicar carpeta se crea y comparte `~/shared` en Linux/macOS o `C:\shared` en Windows. Para elegir otra:

```bash
python3 simple_share.py ~/Descargas/para-compartir
```

La consola muestra la URL de red y un código de seis cifras que cambia cada 30 segundos. Abre la URL desde el otro dispositivo e introduce el código. La sesión permanece activa hasta reiniciar el servidor. `Ctrl+C` detiene el programa.

En terminales interactivos, el panel se redibuja en la misma pantalla al cambiar su tamaño. Muestra los eventos recientes dentro del panel y devuelve la pantalla anterior al salir. Las peticiones HTTP se guardan en `simple_share_logs/` junto al script; usa `-v` para verlas también en el panel.

## Paneles de control

```bash
python3 simple_share.py --gui   # ventana Tkinter
python3 simple_share.py --web   # panel en el navegador local
```

Ambos paneles permiten iniciar y detener el servidor, abrir la carpeta y abrir la URL de archivos. `--gui` abre automáticamente el panel web si Tkinter no está disponible o no puede abrir una ventana. El panel web escucha solo en `127.0.0.1` y muestra su URL en la terminal por si el navegador no se abre automáticamente. `--web-gui` se conserva como alias de `--web`.

En Windows, `pythonw.exe simple_share.py --gui` abre la ventana sin consola.

## Opciones

| Opción | Uso |
| --- | --- |
| `directory` | Carpeta compartida; se crea si no existe. |
| `-p`, `--port` | Puerto del servidor de archivos (predeterminado: `8000`). |
| `-b`, `--bind` | Dirección de escucha (predeterminada: `0.0.0.0`). |
| `--max-upload-mb` | Límite por archivo en MB (predeterminado: `2048`). |
| `--gui` | Panel Tkinter con fallback web. |
| `--web` | Panel web local. |
| `-v`, `--verbose` | Mostrar peticiones HTTP en la consola. |

Ejemplos:

```bash
python3 simple_share.py -p 8080 ~/Compartir
python3 simple_share.py --bind 127.0.0.1
python3 simple_share.py --max-upload-mb 500 -v
```

## Seguridad y límites

Simple Share está pensado para **redes locales de confianza**, no para publicarlo en Internet. Los dispositivos de la red necesitan el código temporal; el acceso desde este equipo mediante `localhost` o una dirección de loopback entra directamente. Cada arranque crea un secreto y una sesión nuevos. Las operaciones de escritura comprueban el origen de la petición, y las rutas se mantienen dentro de la carpeta compartida. No se muestran enlaces simbólicos.

La conexión usa **HTTP sin cifrar**: otros participantes de una red no confiable podrían observar las transferencias. No abras el puerto al Internet público ni compartas archivos sensibles por una red que no controles. El borrado es permanente y no pasa por la papelera.

Si otros dispositivos no pueden acceder, comprueba que estén en la misma red, que uses la URL «Red local» y que el firewall permita el puerto elegido. `--bind 127.0.0.1` limita el servidor de archivos a este equipo.

El programa es un único archivo basado en la biblioteca estándar de Python. La interfaz web funciona en navegadores modernos sin instalar nada en los dispositivos clientes.
