#!/usr/bin/env python3
import scapy.all as scapy
import argparse
import sys


def obter_argumentos(args_lista=None):
    """Configura e analisa os argumentos da linha de comando."""
    parser = argparse.ArgumentParser(description="Scanner de Rede Local Profissional")
    parser.add_argument("-t", "--target", dest="target", required=True, help="IP ou sub-rede alvo (ex: 192.168.1.0/24)")
    # O args_lista permite injetarmos argumentos falsos durante os testes
    return parser.parse_args(args_lista)


def processar_dados_rede(lista_respostas_scapy):
    """
    Recebe os dados brutos do Scapy e os transforma em uma lista de dicionários limpa.
    (Esta é a nossa função principal de lógica, perfeita para ser testada).
    """
    clientes_encontrados = []
    for elemento in lista_respostas_scapy:
        # elemento[1] é a resposta recebida (o pacote de volta)
        ip_cliente = elemento[1].psrc
        mac_cliente = elemento[1].hwsrc
        clientes_encontrados.append({"ip": ip_cliente, "mac": mac_cliente})
    return clientes_encontrados


def escanear_rede(ip):
    """Função que interage com a placa de rede (Difícil de testar sem root, então isolamos)."""
    requisicao_arp = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    pacote_arp_broadcast = broadcast / requisicao_arp

    try:
        # timeout=1 e verbose=False evitam poluir a tela
        respostas = scapy.srp(pacote_arp_broadcast, timeout=1, verbose=False)[0]
        return processar_dados_rede(respostas)
    except Exception as e:
        print(f"[!] Erro de rede: {e}")
        return []


def exibir_resultados(lista_clientes):
    """Formata a saída para o terminal."""
    print("-----------------------------------------")
    print("IP\t\t\tEndereço MAC")
    print("-----------------------------------------")
    for cliente in lista_clientes:
        print(f"{cliente['ip']}\t\t{cliente['mac']}")


if __name__ == "__main__":
    if not scapy.conf.interactive and scapy.conf.L3socket is None:
        sys.stderr.write("ERRO: O Scanner precisa de privilégios de administrador.\n")
        sys.exit(1)

    argumentos = obter_argumentos()
    print(f"\n[+] Escaneando: {argumentos.target} ...")

    resultados = escanear_rede(argumentos.target)

    if resultados:
        exibir_resultados(resultados)
    else:
        print("[-] Nenhum dispositivo encontrado ou erro na rede.")