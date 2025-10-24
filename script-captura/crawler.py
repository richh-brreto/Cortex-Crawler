import pandas as pd
import psutil
import time
import os
from datetime import datetime
from uuid import getnode as get_mac
from pynvml import *
import mysql.connector
import socket
import sys 
import subprocess

# Pega o nome e IP da máquina
nome_maquina = socket.gethostname()
ip = socket.gethostbyname(nome_maquina)

# Configuração pra conectar no banco
try:
    conexao = mysql.connector.connect(
        host="localhost", # para apresentação colocar o IP do servidor
        user="aluno",
        password="sptech",
        database="cortex"
    )
    cursor = conexao.cursor()

    #  verificando se a máquina com este IP e Hostname já existe
    query_verifica = "SELECT id_modelo FROM modelo WHERE ip = %s AND hostname = %s"
    cursor.execute(query_verifica, (ip, nome_maquina))
    resultado = cursor.fetchone()

   
    if resultado is None:
        print(f"Log: Máquina com IP {ip} e Hostname {nome_maquina} não cadastrada.")
        print("O script não será executado.")
        sys.exit()  
    else:
        
        print(f"Máquina com IP {ip} e Hostname {nome_maquina} encontrada. Iniciando script.")

    # Fechar a conexão de verificação
    cursor.close()
    conexao.close()

except mysql.connector.Error as err:
    print(f"Erro ao conectar com o banco de dados: {err}")
    print("O script não pode continuar sem a verificação no banco.")
    sys.exit() # Encerra se não conseguir conectar ao banco

# --- Configurações do projeto ---
DURACAO_CAPTURA = 1 * 60 
CAMINHO_PASTA = 'dados_monitoramento'
MAC_ADRESS = get_mac()
NOME_ARQUIVO = f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')} - {MAC_ADRESS}.csv"
NOME_ARQUIVO_PROCESSO = f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}-Processos {MAC_ADRESS}.csv"
CAMINHO_ARQUIVO = os.path.join(CAMINHO_PASTA, NOME_ARQUIVO)
CAMINHO_ARQUIVO_PROCESSO = os.path.join(CAMINHO_PASTA, NOME_ARQUIVO_PROCESSO)
NOME_LOG = f"log_processamento_{MAC_ADRESS}.csv"
CAMINHO_LOG = os.path.join(CAMINHO_PASTA, NOME_LOG)
NOME_CHUNK = f"chunks_processados_{MAC_ADRESS}.csv"
CAMINHO_CHUNKS = os.path.join(CAMINHO_PASTA, NOME_CHUNK)


# --- Funções de coletar dados de máquina  ---
def coletar_dados_hardware():
    ultima_io = psutil.disk_io_counters()
    ultimo_tempo = time.time()

    time.sleep(3)
    # isso aqui é pra pegar o GPU
    gpu_usage = 0
    try:
        nvmlInit()
        gpu_count = nvmlDeviceGetCount()
        if gpu_count > 0:
            handle = nvmlDeviceGetHandleByIndex(0)
            utilization = nvmlDeviceGetUtilizationRates(handle)
            gpu_usage = utilization.gpu  # pega o percentual de uso da GPU
    except Exception as e:
        gpu_usage = 0  # caso de falha na leitura = 0%
    finally:
        try:
            nvmlShutdown()
        except:
            pass  # ignora falha no shutdown (se der erro acima)

        atual_io = psutil.disk_io_counters()
        atual_tempo = time.time()
        tempo_decorrido = atual_tempo - ultimo_tempo

    disco_uso_percent = 0
    if tempo_decorrido > 0:
        if hasattr(atual_io, 'busy_time') and hasattr(ultima_io, 'busy_time'): #busca se tem o atributo busy_time (tempo ocupado)
            # usa o tempo que o disco esteve ocupado
            busy_diff = atual_io.busy_time - ultima_io.busy_time
            disco_uso_percent = round((busy_diff / (tempo_decorrido * 1000)) * 100, 1)
        else:
            # calcula baseado na soma de leitura e escrita
            read_diff = atual_io.read_bytes - ultima_io.read_bytes # calcula quantos bytes foram lidos desde a última coleta
            write_diff = atual_io.write_bytes - ultima_io.write_bytes # calcula quantos bytes foram escritos desde a última coleta
            total_diff = read_diff + write_diff # total de bytes lidos e escritos
            disco_uso_percent = round(min(100, total_diff / (1024 ** 2) / tempo_decorrido), 1) # converte para MB/s e calcula o percentual

    ultima_io = atual_io
    ultimo_tempo = atual_tempo

    return {
        'ip': ip,
        'hostname': nome_maquina,
        'timestamp': datetime.now().strftime('%Y-%m-%d_%H-%M-%S'),
        'cpu': psutil.cpu_percent(),
        'ram': psutil.virtual_memory().percent,
        'armazenamento': psutil.disk_usage('/').percent,
        'disco_uso': disco_uso_percent,
        'mac': MAC_ADRESS,
        'gpu': gpu_usage
    }

#função para coletar processos
def coletar_dados_processos():
    processos_info = []

# aqui pegando a GPU por processo e fazendo um percentual com o nvidia-smi
   
    gpu_usage_por_pid = {}
    total_mem = 1  # evita divisão por zero
    try:
        # pega memória total da GPU
        result_total = subprocess.run(
            ['nvidia-smi', '--query-gpu=memory.total', '--format=csv,noheader,nounits'],
            stdout=subprocess.PIPE
        )
        total_mem = int(result_total.stdout.decode().strip()) * 1024 * 1024  # converte para bytes

        # pega processos que estão usando a GPU
        result_procs = subprocess.run(
            ['nvidia-smi', '--query-compute-apps=pid,used_gpu_memory', '--format=csv,noheader,nounits'],
            stdout=subprocess.PIPE
        )
        linhas = result_procs.stdout.decode().strip().split('\n')
        for linha in linhas:
            try:
                pid_str, mem_str = linha.split(', ')
                pid = int(pid_str)
                mem_bytes = int(mem_str) * 1024 * 1024  # converte para bytes
                gpu_usage_por_pid[pid] = mem_bytes
            except ValueError:
                continue
    except:
        gpu_usage_por_pid = {}
        total_mem = 1

    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    time.sleep(1)

    for proc in psutil.process_iter():
        try:
            cpu = round(proc.cpu_percent(interval=None)/ psutil.cpu_count(logical=True),1)
            disco = round((proc.io_counters().write_bytes / (1024 ** 2)),1)
            ram = round((proc.memory_info().rss * 100 / psutil.virtual_memory().total),1)

            pid = proc.pid
            used_gpu_mem = gpu_usage_por_pid.get(pid, 0) # memória usada pela GPU por este processo
            gpu_percent = round((used_gpu_mem / total_mem) * 100, 1) if used_gpu_mem else 0 # porcentagem do uso da gpu modo gambiarra

            if cpu > 0 or ram > 1 or disco > 1:
                if ram < 1:
                    ram = 0
                if disco < 1:
                    disco = 0
                processos_info.append({ 
                    'ip': ip,
                    'hostname':nome_maquina,
                    'timestamp' : datetime.now().strftime('%Y-%m-%d_%H-%M-%S'),
                    'processo' : proc.name(),
                    'cpu' : cpu,
                    'ram' : ram,
                    'dados_gravados' : disco,
                    'mac' : MAC_ADRESS,
                    'gpu' : gpu_percent,
                    'disco_uso' : proc.io_counters().write_bytes # aqui vai pegar o quanto o processo em si ta usando de disco em bytes
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processos_info
    
def salvar_arquivo(dataFrame,CAMINHO):
    if os.path.exists(CAMINHO):
        dataFrame.to_csv(CAMINHO, mode='a', header=False, index=False)
    else:
        dataFrame.to_csv(CAMINHO, index=False)

def registrar_log(mensagem):
    log_data = pd.DataFrame([{
        'ip':ip,
        'hostname':nome_maquina,
        'timestamp': datetime.now(),
        'evento': mensagem,
        'mac' : MAC_ADRESS
    }])
    salvar_arquivo(log_data,CAMINHO_LOG)

def adicionar_a_chunks(nome_arquivo):
    chunk_data = pd.DataFrame([{
        'timestamp': datetime.now(),
        'nome_arquivo': nome_arquivo
    }])
    salvar_arquivo(chunk_data,CAMINHO_CHUNKS)

def redefinir_caminho():
    global NOME_ARQUIVO, CAMINHO_ARQUIVO, NOME_ARQUIVO_PROCESSO, CAMINHO_ARQUIVO_PROCESSO
    NOME_ARQUIVO = f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')} - {MAC_ADRESS}.csv"
    CAMINHO_ARQUIVO = os.path.join(CAMINHO_PASTA, NOME_ARQUIVO)
    NOME_ARQUIVO_PROCESSO = f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}-Processos {MAC_ADRESS}.csv"
    CAMINHO_ARQUIVO_PROCESSO = os.path.join(CAMINHO_PASTA, NOME_ARQUIVO_PROCESSO)
    return CAMINHO_ARQUIVO,NOME_ARQUIVO, NOME_ARQUIVO_PROCESSO, CAMINHO_ARQUIVO_PROCESSO

def check_blacklist(conexao):
    nomes = []
    try:
        cur = conexao.cursor()
        cur.execute("SELECT nome FROM black_list")
        rows = cur.fetchall()
        nomes = [r[0] for r in rows if r and r[0]]
        cur.close()
    except Exception as e:
        registrar_log(f"Erro ao carregar blacklist do banco: {e}")
    return nomes

def verificar_blacklist_processos(processos, nomes):
    nomes_lower = [n.lower() for n in nomes]
    for proc in psutil.process_iter(['name']):
        try:
            nome_proc = proc.info['name']
            if nome_proc and nome_proc.lower() in nomes_lower:
                # registra evento e chunk antes de matar
                registrar_log(f"Processo da blacklist detectado: {nome_proc}")
                adicionar_a_chunks(nome_proc)

                # tenta matar (pode gerar AccessDenied se nao tiver admin)
                try:
                    proc.kill()
                    registrar_log(f"Processo {nome_proc} foi encerrado automaticamente.")
                except psutil.NoSuchProcess:
                    registrar_log(f"Processo {nome_proc} já não existia ao tentar matar.")
                except psutil.AccessDenied:
                    registrar_log(f"Sem permissão para encerrar o processo {nome_proc}.")
                except Exception as e:
                    registrar_log(f"Erro ao encerrar processo {nome_proc}: {e}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

# --- Lógica principal  ---
def main():
    print("Iniciando o monitoramento. Pressione Ctrl+C a qualquer momento para sair.")
    if not os.path.exists(CAMINHO_PASTA):
        os.makedirs(CAMINHO_PASTA)
    inicio_captura = time.time()
    dados_coletados = []
    processos = []
    redefinir_caminho()
    while True:
        try:
            time.sleep(1)
            dados_coletados.append(coletar_dados_hardware())

            processos = coletar_dados_processos()

            df_dados = pd.DataFrame(dados_coletados)
            df_dados.to_csv(CAMINHO_ARQUIVO, index=False)

            df_processo = pd.DataFrame(processos)
            df_processo.to_csv(CAMINHO_ARQUIVO_PROCESSO, index=False)

            nomes = []
            try:
                conexao = mysql.connector.connect(
                    host="localhost",
                    user="aluno",
                    password="sptech",
                    database="cortex"
                )
                nomes = check_blacklist(conexao)
                conexao.close()
            except Exception as e:
                registrar_log(f"Erro ao conectar/consultar blacklist: {e}")
                nomes = []
            # se houver nomes na blacklist, verificar e encerrar (após gravação)
            if nomes:
                verificar_blacklist_processos(processos, nomes)
            
            if time.time() - inicio_captura >= DURACAO_CAPTURA:
                redefinir_caminho()
                registrar_log(f"Novo arquivo de dados criado: {NOME_ARQUIVO}")
                registrar_log(f"Novo arquivo de dados criado: {NOME_ARQUIVO_PROCESSO}")
                print(f"Captura finalizada. Dados salvos em {CAMINHO_ARQUIVO} e em {CAMINHO_ARQUIVO_PROCESSO}")
                adicionar_a_chunks(NOME_ARQUIVO_PROCESSO)
                adicionar_a_chunks(NOME_ARQUIVO)
                inicio_captura = time.time()
                dados_coletados = []
                processos = []
        except KeyboardInterrupt:
            print("\nMonitoramento interrompido pelo usuário.")
            registrar_log("Monitoramento interrompido manualmente.")
            break
        except Exception as e:
            print(f"Ocorreu um erro: {e}")
            registrar_log(f"ERRO: {e}")
            break

if __name__ == "__main__":
    main()