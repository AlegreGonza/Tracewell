"""Mirada de SOLO LECTURA al sistema donde corre Tracewell (procesos, puertos, memoria, servicios, inicio).

Nada de este paquete modifica el sistema: no termina procesos, no cambia configuración, no escribe en el registro.
Todo sale de `psutil` (import perezoso y opcional) y, para unos pocos datos de Windows, de lecturas del registro
o de un único comando de consulta.
"""
