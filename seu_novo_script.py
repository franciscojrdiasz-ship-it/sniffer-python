from scapy.all import *
import sys
#Scanner de  Portas
# Função que será chamada para cada pacote capturado
def analisar_pacote(pacote):
    print("--- Novo Pacote ---")
    
    # Verifica se o pacote tem a camada IP (Internet Protocol)
    if pacote.haslayer(IP):
        ip_origem = pacote[IP].src
        ip_destino = pacote[IP].dst
        protocolo = pacote[IP].proto
        
        print(f"IP Origem: {ip_origem}")
        print(f"IP Destino: {ip_destino}")
        
        # Analisando protocolos da camada de transporte (TCP ou UDP)
        if pacote.haslayer(TCP):
            porta_origem = pacote[TCP].sport
            porta_destino = pacote[TCP].dport
            print(f"Protocolo: TCP")
            print(f"Porta de Origem: {porta_origem}")
            print(f"Porta de Destino: {porta_destino}")

            # Tentando extrair dados brutos (payload), como em uma requisição HTTP
            if pacote.haslayer(Raw):
                # .load para obter os bytes e .decode para tentar transformar em texto
                payload = pacote[Raw].load.decode('utf-8', errors='ignore')
                print("\n[+] Dados (Payload):")
                print(payload.strip())

        elif pacote.haslayer(UDP):
            porta_origem = pacote[UDP].sport
            porta_destino = pacote[UDP].dport
            print(f"Protocolo: UDP")
            print(f"Porta de Origem: {porta_origem}")
            print(f"Porta de Destino: {porta_destino}")

# Função principal do sniffer
def iniciar_sniffer():
    print("Analisador de tráfego iniciado. Pressione CTRL+C para parar.")
    # 'prn' define a função que será executada para cada pacote
    # 'store=0' evita que a Scapy armazene os pacotes na memória
    sniff(prn=analisar_pacote, store=0)

if __name__ == '__main__':
    try:
        iniciar_sniffer()
    except KeyboardInterrupt:
        print("\nAnalisador interrompido pelo usuário. Saindo.")
        sys.exit(0)
    except Exception as e:
        print(f"Ocorreu um erro: {e}")

# ... (mantenha o resto do código do Passo 2) ...

def iniciar_sniffer(filtro):
    print(f"Analisador de tráfego iniciado com o filtro: '{filtro}'. Pressione CTRL+C para parar.")
    # Adicionamos o argumento 'filter'
    sniff(filter=filtro, prn=analisar_pacote, store=0)

if __name__ == '__main__':
    # Exemplo de filtro: capturar apenas tráfego TCP na porta 80 (HTTP)
    filtro_exemplo = "tcp and port 80" 
    
    # Outros exemplos de filtro que você pode testar:
    # filtro_exemplo = "udp and port 53"  # Apenas tráfego DNS
    # filtro_exemplo = "host 1.1.1.1"      # Tráfego de ou para o IP 1.1.1.1
    # filtro_exemplo = "port 443"         # Apenas tráfego na porta 443 (HTTPS)

    try:
        iniciar_sniffer(filtro_exemplo)
    except KeyboardInterrupt:
        print("\nAnalisador interrompido pelo usuário. Saindo.")
        sys.exit(0)
    except Exception as e:
        print(f"Ocorreu um erro: {e}")
        
