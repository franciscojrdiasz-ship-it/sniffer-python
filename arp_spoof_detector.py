#!/usr/bin/env python3

import scapy.all as scapy
import argparse
import sys
import logging
from colorama import init, Fore, Style

# Inicializa o Colorama para garantir que as cores funcionem no Windows
init(autoreset=True)


class DetectorARPSpoofing:
    """
    Sistema de Detecção de Intrusão (IDS) focado em ataques de Envenenamento ARP.
    """

    def __init__(self, interface=None, arquivo_log="alertas_ids.log"):
        self.interface = interface
        self.tabela_arp = {}  # Memória do sistema: armazena os IPs e MACs confiáveis

        # Configuração do Sistema de Logs Profissional
        logging.basicConfig(
            filename=arquivo_log,
            level=logging.WARNING,  # Só salva no arquivo o que for do nível WARNING para cima
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        # Cria um "logger" específico para esta classe
        self.logger = logging.getLogger("IDS_ARP")

    def get_mac(self, ip):
        """Obtém o MAC real de um IP realizando uma requisição ARP ativa."""
        try:
            pacote_arp = scapy.ARP(pdst=ip)
            pacote_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            pacote_final = pacote_broadcast / pacote_arp

            # timeout baixo para não travar o sniffer principal
            resposta = scapy.srp(pacote_final, timeout=1, verbose=False)[0]
            if resposta:
                return resposta[0][1].hwsrc
        except Exception:
            pass
        return None

    def analisar_pacote(self, pacote):
        """Função de callback que analisa cada pacote interceptado."""
        # Se o pacote tiver a camada ARP e for uma resposta (op=2)
        if pacote.haslayer(scapy.ARP) and pacote[scapy.ARP].op == 2:
            try:
                ip_anunciado = pacote[scapy.ARP].psrc
                mac_anunciado = pacote[scapy.ARP].hwsrc

                # 1. Se já conhecemos este IP, vamos verificar se o MAC mudou
                if ip_anunciado in self.tabela_arp:
                    mac_conhecido = self.tabela_arp[ip_anunciado]

                    if mac_conhecido != mac_anunciado:
                        # [!!!] ALERTA DE ATAQUE DETECTADO [!!!]
                        mensagem_alerta = f"Ataque ARP Spoofing detectado! IP: {ip_anunciado} | MAC Legítimo: {mac_conhecido} | MAC Falso: {mac_anunciado}"

                        # Imprime na tela em VERMELHO
                        print(Fore.RED + Style.BRIGHT + f"[CRÍTICO] {mensagem_alerta}")

                        # Salva a evidência no arquivo de log com timestamp
                        self.logger.critical(mensagem_alerta)

                # 2. Se não conhecemos o IP, vamos descobrir seu MAC real e salvar na memória
                else:
                    mac_real = self.get_mac(ip_anunciado)
                    if mac_real:
                        self.tabela_arp[ip_anunciado] = mac_real
                        print(Fore.GREEN + f"[INFO] Novo dispositivo registrado: IP {ip_anunciado} -> MAC {mac_real}")

            except IndexError:
                pass

    def iniciar_monitoramento(self):
        """Inicia o motor do sniffer na interface de rede."""
        print(Fore.CYAN + Style.BRIGHT + "[*] IDS Iniciado. Monitorando tráfego ARP...")
        print(Fore.CYAN + f"[*] Evidências de ataques serão salvas em: alertas_ids.log")
        print(Fore.YELLOW + "[*] Pressione CTRL+C para parar.\n")

        # Filtro BPF estrito para performance: só queremos tráfego ARP
        scapy.sniff(iface=self.interface, store=False, prn=self.analisar_pacote, filter="arp")


# --- Ponto de Entrada do Script ---
if __name__ == "__main__":
    # Verificação de segurança: Scapy exige modo administrador
    if not scapy.conf.interactive and scapy.conf.L3socket is None:
        print(Fore.RED + "ERRO: Este script de segurança exige privilégios de Administrador (root/Admin).")
        sys.exit(1)

    # Configuração de argumentos de linha de comando para torná-lo uma ferramenta CLI real
    parser = argparse.ArgumentParser(description="IDS para detecção de ARP Spoofing")
    parser.add_argument("-i", "--interface", dest="interface", help="Interface de rede específica (opcional)")
    args = parser.parse_args()

    try:
        # Instancia o objeto da nossa classe (Programação Orientada a Objetos)
        detector = DetectorARPSpoofing(interface=args.interface)
        detector.iniciar_monitoramento()

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Monitoramento interrompido pelo usuário. Encerrando IDS.")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"\n[!] Falha crítica no sistema: {e}")
