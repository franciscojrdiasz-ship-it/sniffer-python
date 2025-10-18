# Importa a biblioteca Scapy
from scapy.all import *

print("Iniciando a captura de 1 pacote...")

# sniff() é a função principal da Scapy para capturar pacotes.
# count=1 diz para capturar apenas um pacote e depois parar.
pacote = sniff(count=1)

# A Scapy armazena os pacotes capturados em uma lista.
# Como capturamos apenas um, ele estará na posição 0.
print("\nPacote capturado! Exibindo detalhes:")
pacote[0].show()
