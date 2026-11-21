"""Herramientas de soporte de red de SOLO LECTURA.

Ninguna cambia la configuración del equipo: no renuevan la IP, no limpian el DNS, no corrigen la hora, no tocan el
registro. Miden, consultan y explican; cuando detectan un problema, el resultado trae el comando que la persona
podría ejecutar por su cuenta (solo como texto).

Lo único que sale de la máquina son pruebas que el usuario pide a propósito (un ping, una conexión TCP, una consulta
de hora), y cada pantalla dice a quién se contacta.
"""
