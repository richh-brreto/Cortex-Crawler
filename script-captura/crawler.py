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
import platform
import boto3

# Pega o nome e IP da máquina
nome_maquina = socket.gethostname()
ip = socket.gethostbyname(nome_maquina)

# pegar dados da env
from dotenv import load_dotenv
load_dotenv()

# Configuração pra conectar no banco
try:
    conexao = mysql.connector.connect(
        host=os.getenv("DATABASE_HOST"),
        user=os.getenv("DATABASE_USER"),
        password=os.getenv("DATABASE_PASSWORD"),
        database=os.getenv("DATABASE_USED")
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
    sistema = platform.system()
   
    gpu_usage_por_pid = {}

    # ----- aqui se for windows -------
    if sistema == "Windows":
        try:
            import wmi
            f = wmi.WMI(namespace='root\\CIMV2')

            # tabela de contadores de GPU (igual ao Gerenciador de Tarefas)
            gpu_infos = f.Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine()
            for info in gpu_infos:
                # Exemplo: "pid_1234_luid_0x00000000_0_engtype_3D"
                if "pid_" in info.Name:
                    partes = info.Name.split("_")
                    for i, p in enumerate(partes):
                        if p == "pid" and i + 1 < len(partes):
                            try:
                                pid = int(partes[i + 1])
                                gpu_usage_por_pid[pid] = gpu_usage_por_pid.get(pid, 0) + int(info.UtilizationPercentage)
                            except ValueError:
                                continue
        except Exception as e:
            gpu_usage_por_pid = {}

    # ----- aqui se for linux -------
    elif sistema == "Linux":
        try:
            result = subprocess.run(['nvidia-smi', 'pmon', '-c', '1'], stdout=subprocess.PIPE)
            linhas = result.stdout.decode().strip().split('\n')
            for linha in linhas[2:]:  # pula cabeçalho
                partes = linha.split()
                if len(partes) >= 6:
                    try:
                        pid = int(partes[1])
                        mem = int(partes[4])  # uso de memória da GPU (%)
                        gpu_usage_por_pid[pid] = mem
                    except ValueError:
                        continue
        except Exception:
            gpu_usage_por_pid = {}

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
            gpu_percent = gpu_usage_por_pid.get(pid, 0)

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

def send_to_s3(local_folder, bucket_name=None, s3_prefix='data/'):
# pra pegar o bucket do .env (nao esquecer de colocar lá)
    if not bucket_name:
        bucket_name = os.getenv("AWS_BUCKET_NAME")
# é necessário caso vc não tenha configurado o ambiente, em geral vai ser mais rápido estar aqui senao vai ter q configurar
    s3_client = boto3.client("s3",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_acess_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        aws_session_token=os.getenv("AWS_SESSION_TOKEN")
    )

    if not os.path.exists(local_folder):
        registrar_log(f"Pasta {local_folder} não existe para upload.")
        return False
    
    try: 
        uploaded_files = 0

#vendo lista no S3 para evitar duplicatas
        existing_files = [] 
        try:
            response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=s3_prefix)
            if "Contents" in response:
                existing_files = [obj["Key"].split("/")[-1] for obj in response["Contents"]]
        except Exception:
            pass

        for filename in os.listdir(local_folder):
            local_path = os.path.join(local_folder, filename)

            if filename not in existing_files:
                if os.path.isfile(local_path):
                    s3_key = f"{s3_prefix}{filename}" if s3_prefix else filename
                    s3_client.upload_file(local_path, bucket_name, s3_key)
                    print(f"Enviado {local_path} para s3://{bucket_name}/{s3_key}")
                    uploaded_files += 1

        print(f"Upload concluído, {uploaded_files} arquivo(s) enviado(s)")
        return True
        
    except Exception as e:
        print(f"Erro ao enviar pasta para S3: {e}")
        return False

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

                try:
                    sucesso = send_to_s3(
                        local_folder=CAMINHO_PASTA,
                        bucket_name=os.getenv("AWS_BUCKET_NAME"),
                        s3_prefix="dados_monitoramento/"
                    )
                    if sucesso:
                        registrar_log("Upload S3 concluído com sucesso.")
                    else:
                        registrar_log("Falha no upload para S3.")
                except Exception as e:
                    registrar_log(f"Erro no upload para S3: {e}")

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