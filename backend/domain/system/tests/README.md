# Documentación de `backend/domain/system/tests`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## fakes.py

psutil FALSO para probar backend/domain/system sin tocar el sistema real.

Cualquier función que MODIFIQUE el sistema (kill, terminate, suspend, resume, nice, ionice, cpu_affinity, send_signal...)
o cualquier otra que el código no debería llamar hace fallar el test con AssertionError.


### Funciones y clases


**`FakeProcess`**: Un proceso. `deny` = nombres de lectura que fallan con AccessDenied; `gone` = los que fallan con NoSuchProcess.


## test_autostart.py

Tests de backend/domain/system/autostart.py (servicios y programas de inicio): todo con fakes, nada del sistema real.


### Notas del código

- `test_inicio_windows_nunca_escribe_en_el_registro`: si llamara a SetValue/CreateKey/Delete* el fake lanza AssertionError
- `test_inicio_windows_nunca_escribe_en_el_registro`: y la apertura es la de lectura por defecto (sin pedir KEY_WRITE / KEY_SET_VALUE)


## test_readonly.py

Garantía de SOLO LECTURA: ningún módulo de backend/domain/system (ni sus rutas) puede modificar el sistema.


### Funciones y clases


**`code_of`**: Código sin comentarios ni cadenas de documentación (para no confundir texto explicativo con llamadas).


### Notas del código

- `test_corriendo_todo_con_un_psutil_que_explota_si_se_modifica`: (si alguno hubiera llamado a kill/terminate/etc., FakeProcess/FakePsutil habrían lanzado AssertionError)

