# Documentación de `samples`

Texto completo movido desde el código. En los `.py` quedan solo comentarios cortos.


## generate_demo.py

Genera samples/demo.pcap: tráfico SINTÉTICO para el modo demo.

Contiene tráfico normal (DNS, HTTP, ICMP, ARP) y tres comportamientos que
disparan las reglas: escaneo de puertos, login FTP en texto claro y una
consulta DNS con aspecto de túnel. Es determinista: mismo archivo cada vez.

Uso (desde la raíz del proyecto):  python samples/generate_demo.py

