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
from dotenv import load_dotenv

# --- Config e identificação ---
load_dotenv()

# nome_maquina = socket.gethostname()
# ip = socket.gethostbyname(nome_maquina)
nome_maquina = "DESKTOP-N2E1DHL"
ip = "10.102.136.40"

# --- Configurações do projeto ---
DURACAO_CAPTURA = 1 * 60 
CAMINHO_PASTA = 'dados_monitoramento'



DRY_RUN = True  # True = simula, False = mata processos

# --- Processos protegidos ---
PROTECTED = {
    "system", "idle", "init", "explorer.exe", "explorer", "python.exe", "python", "mysqld", "mysqld.exe",
    "svchost.exe", "svchost", "winlogon.exe", "csrss.exe", "services.exe", "lsass.exe", "smss.exe",
    "taskhostw.exe", "systemd", "kthreadd", "rcu_sched"
}

# --- Verificação inicial ---
try:
    conexao = mysql.connector.connect(
        host="localhost",
        user="aluno",
        password="sptech",
        database="cortex"
    )
    cursor = conexao.cursor(buffered=True)
    query_verifica = "select m.id_modelo, z.id_zona , e.id from modelo as m inner join cliente as c on m.fk_cliente =  c.id_cliente inner join empresa as e on c.fk_empresa = e.id inner join zonadisponibilidade as z on z.id_zona = m.fk_zona_disponibilidade where m.ip = %s and m.hostname = %s;"
    cursor.execute(query_verifica, (ip, nome_maquina))
    resultado = cursor.fetchone()

    if resultado is None:
        print(f"Máquina {ip} / {nome_maquina} não cadastrada. Script finalizado.")
        cursor.close()
        conexao.close()
        sys.exit()
    else:
        fk_modelo = resultado[0]
        fk_zona = resultado[1]
        fk_empresa = resultado[2]
        print(f"Máquina encontrada (fk_modelo={fk_modelo}, fk_zona={fk_zona}, fk_empresa={fk_empresa}). Iniciando script.")

    cursor.close()
    conexao.close()

except mysql.connector.Error as err:
    print(f"Erro no banco: {err}")
    sys.exit()

# --- Configurações do projeto que dependem do banco ---

NOME_ARQUIVO = f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')};{fk_modelo};{fk_zona};{fk_empresa}.csv" #AQUI
NOME_ARQUIVO_PROCESSO = f"Processos;{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')};{fk_modelo};{fk_zona};{fk_empresa};.csv" #AQUI
CAMINHO_ARQUIVO = os.path.join(CAMINHO_PASTA, NOME_ARQUIVO)
CAMINHO_ARQUIVO_PROCESSO = os.path.join(CAMINHO_PASTA, NOME_ARQUIVO_PROCESSO)
NOME_LOG = f"log_processamento;{fk_modelo};{fk_zona};{fk_empresa}.csv" #AQUI
CAMINHO_LOG = os.path.join(CAMINHO_PASTA, NOME_LOG)
NOME_CHUNK = f"chunks_processados;{fk_modelo};{fk_zona};{fk_empresa}.csv"  #AQUI
CAMINHO_CHUNKS = os.path.join(CAMINHO_PASTA, NOME_CHUNK)

# --- Funções de coleta ---
def coletar_dados_hardware():
    ultima_io = psutil.disk_io_counters()
    ultimo_tempo = time.time()

    time.sleep(3)
    gpu_usage = 0
    try:
        nvmlInit()
        gpu_count = nvmlDeviceGetCount()
        if gpu_count > 0:
            handle = nvmlDeviceGetHandleByIndex(0)
            utilization = nvmlDeviceGetUtilizationRates(handle)
            gpu_usage = utilization.gpu
    except Exception:
        gpu_usage = 0
    finally:
        try:
            nvmlShutdown()
        except:
            pass

        atual_io = psutil.disk_io_counters()
        atual_tempo = time.time()
        tempo_decorrido = atual_tempo - ultimo_tempo

    disco_uso_percent = 0
    if tempo_decorrido > 0:
        if hasattr(atual_io, 'busy_time') and hasattr(ultima_io, 'busy_time'):
            busy_diff = atual_io.busy_time - ultima_io.busy_time
            disco_uso_percent = round((busy_diff / (tempo_decorrido * 1000)) * 100, 1)
        else:
            read_diff = atual_io.read_bytes - ultima_io.read_bytes
            write_diff = atual_io.write_bytes - ultima_io.write_bytes
            total_diff = read_diff + write_diff
            disco_uso_percent = round(min(100, total_diff / (1024 ** 2) / tempo_decorrido), 1)

    return {
        'fk_modelo': fk_modelo,
        'fk_zona': fk_zona,
        'fk_empresa' : fk_empresa,
        'timestamp': datetime.now().strftime('%Y-%m-%d_%H-%M-%S'),
        'cpu': psutil.cpu_percent(),
        'ram': psutil.virtual_memory().percent,
        'armazenamento': psutil.disk_usage('/').percent,
        'disco_uso': disco_uso_percent,
    }

def coletar_dados_processos():
    processos_info = []
    sistema = platform.system()
    gpu_usage_por_pid = {}

    if sistema == "Windows":
        try:
            import wmi
            f = wmi.WMI(namespace='root\\CIMV2')
            gpu_infos = f.Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine()
            for info in gpu_infos:
                if "pid_" in info.Name:
                    partes = info.Name.split("_")
                    for i, p in enumerate(partes):
                        if p == "pid" and i + 1 < len(partes):
                            try:
                                pid = int(partes[i + 1])
                                gpu_usage_por_pid[pid] = gpu_usage_por_pid.get(pid, 0) + int(info.UtilizationPercentage)
                            except ValueError:
                                continue
        except Exception:
            gpu_usage_por_pid = {}
    elif sistema == "Linux":
        try:
            result = subprocess.run(['nvidia-smi', 'pmon', '-c', '1'], stdout=subprocess.PIPE)
            linhas = result.stdout.decode().strip().split('\n')
            for linha in linhas[2:]:
                partes = linha.split()
                if len(partes) >= 6:
                    try:
                        pid = int(partes[1])
                        mem = int(partes[4])
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
            disco = 0
            try:
                disco = round((proc.io_counters().write_bytes / (1024 ** 2)),1)
            except Exception:
                disco = 0
            try:
                ram = round((proc.memory_info().rss * 100 / psutil.virtual_memory().total),1)
            except Exception:
                ram = 0

            pid = proc.pid
            gpu_percent = gpu_usage_por_pid.get(pid, 0)

            if cpu > 0 or ram > 1 or disco > 1:
                if ram < 1:
                    ram = 0
                if disco < 1:
                    disco = 0
                processos_info.append({
                    'fk_modelo': fk_modelo,
                    'fk_zona':fk_zona,
                    'fk_empresa' : fk_empresa,
                    'timestamp' : datetime.now().strftime('%Y-%m-%d_%H-%M-%S'),
                    'processo' : proc.name(),
                    'cpu' : cpu,
                    'ram' : ram,
                    'dados_gravados' : disco,
                    'gpu' : gpu_percent,
                    'disco_uso' : proc.io_counters().write_bytes if proc.io_counters() else 0
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processos_info

# --- Funções auxiliares ---
def salvar_arquivo(dataFrame,CAMINHO):
    if os.path.exists(CAMINHO):
        dataFrame.to_csv(CAMINHO, mode='a', header=False, index=False)
    else:
        dataFrame.to_csv(CAMINHO, index=False)

def registrar_log(mensagem):
    log_data = pd.DataFrame([{
        'fk_modelo':fk_modelo,
        'fk_zona' : fk_zona,
        'fk_empresa':fk_empresa,
        'timestamp': datetime.now(),
        'evento': mensagem
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
    NOME_ARQUIVO = f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')};{fk_modelo};{fk_zona};{fk_empresa}.csv" #AQUI
    CAMINHO_ARQUIVO = os.path.join(CAMINHO_PASTA, NOME_ARQUIVO)
    NOME_ARQUIVO_PROCESSO = f"Processos;{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')};{fk_modelo};{fk_zona};{fk_empresa};.csv" #AQUI
    CAMINHO_ARQUIVO_PROCESSO = os.path.join(CAMINHO_PASTA, NOME_ARQUIVO_PROCESSO)
    return CAMINHO_ARQUIVO,NOME_ARQUIVO, NOME_ARQUIVO_PROCESSO, CAMINHO_ARQUIVO_PROCESSO

# --- Whitelist ---
def check_whitelist(conexao, fk_modelo): #Essa função retorna os nomes da whitelist, OU SEJA,os processos que devem/podem estar ali
    nomes = set()
    cur = None
    try:
        cur = conexao.cursor(buffered=True)
        cur.execute("SELECT nome FROM whitelist WHERE fk_modelo = %s", (fk_modelo,))
        for r in cur.fetchall():
            if not r or not r[0]:
                continue
            n = str(r[0]).strip().lower()
            if n.endswith(".exe"):
                n = n[:-4]
            nomes.add(os.path.basename(n))
    except Exception as e:
        registrar_log(f"Erro ao carregar whitelist: {e}")
    finally:
        if cur:
            cur.close()
    return nomes

def check_whitelist_matar(conexao, fk_modelo):
    nomes = []
    cur = None
    try:
        cur = conexao.cursor(buffered=True)
        cur.execute("SELECT id_processo, nome, matar FROM whitelist WHERE fk_modelo = %s", (fk_modelo,))
        for r in cur.fetchall():
            if not r or not r[1]:
                continue
            id_whitelist = r[0]
            n = str(r[1]).strip().lower()
            if n.endswith(".exe"):
                n = n[:-4]
            nomes.append((id_whitelist, os.path.basename(n), bool(r[2])))
    except Exception as e:
        registrar_log(f"Erro ao carregar whitelist com matar do banco: {e}")
    finally:
        if cur:
            cur.close()
    return nomes


def aplicar_matar_processos(conexao, whitelist_com_matar, fk_modelo):
    #Aqui mata os processos que ESTÃO na whitelist mas com o matar = true
    for id_whitelist, nome_proc, matar_flag in whitelist_com_matar:
        if not matar_flag:
            continue

        # Normaliza nome do processo do banco
        nome_proc_db = nome_proc.strip().lower()
        if nome_proc_db.endswith(".exe"):
            nome_proc_db = nome_proc_db[:-4]

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                nome_proc_atual = proc.info.get('name') or ''
                nome_proc_norm = os.path.basename(nome_proc_atual.strip()).lower()
                if nome_proc_norm.endswith(".exe"):
                    nome_proc_norm = nome_proc_norm[:-4]

                if nome_proc_norm == nome_proc_db:
                    try:
                        if not DRY_RUN:
                            proc.kill()
                        registrar_log(f"Processo '{nome_proc}' morto por flag matar=True")
                    except psutil.AccessDenied:
                        registrar_log(f"Permissão negada ao tentar matar '{nome_proc}'")
                    except psutil.NoSuchProcess:
                        registrar_log(f"Processo '{nome_proc}' já não existe")
                    except Exception as e:
                        registrar_log(f"Erro desconhecido ao matar '{nome_proc}': {e}")

                    # registra no log_processos
                    try:
                        cur_log = conexao.cursor()
                        cur_log.execute(
                            "INSERT INTO log_processos (nome, fk_modelo) VALUES (%s, %s)",
                            (nome_proc, fk_modelo)
                        )
                        conexao.commit()
                        cur_log.close()
                    except Exception as e:
                        registrar_log(f"Erro ao registrar '{nome_proc}' no log_processos: {e}")

                    # atualiza matar = 0 no banco
                    try:
                        cur = conexao.cursor()
                        cur.execute(
                            "UPDATE whitelist SET matar = 0 WHERE id_processo = %s",
                            (id_whitelist,)
                        )
                        conexao.commit()
                        cur.close()
                    except Exception as e:
                        registrar_log(f"Erro ao atualizar matar=False no banco para '{nome_proc}': {e}")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue



# --- Detectar processos fora da whitelist ---
detected_outside_whitelist = set()
def verificar_whitelist_processos(processos, nomes_set):
    nomes_normalizados = {n.lower() for n in nomes_set}
    for p in processos:
        nome_proc = os.path.basename(p['processo']).lower()
        if nome_proc.endswith(".exe"):
            nome_proc = nome_proc[:-4]
        if nome_proc not in nomes_normalizados and nome_proc not in PROTECTED:
            if nome_proc not in detected_outside_whitelist:
                registrar_log(f"Processo fora da whitelist detectado: {nome_proc}")
                detected_outside_whitelist.add(nome_proc)

def matar_fora_whitelist(conexao, processos, nomes_whitelist):
   
 #Aqui mata os processos ativos q estão fora da blacklist
    nomes_whitelist = {n.lower() for n in nomes_whitelist}

    #  dicionário de processos ativos por nome 
    processos_ativos = {}
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            nome = (proc.info.get('name') or '').strip().lower()
            if nome.endswith(".exe"):
                nome = nome[:-4]
            if nome not in processos_ativos:
                processos_ativos[nome] = []
            processos_ativos[nome].append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # --- Iterar apenas pelos nomes fora da whitelist e protegidos ---
    for nome_proc, lista_proc in processos_ativos.items():
        if nome_proc in nomes_whitelist or nome_proc in PROTECTED:
            continue

        for proc in lista_proc:
            try:
                if not DRY_RUN:
                    proc.kill()
                registrar_log(f"Processo fora da whitelist morto: {nome_proc}")

                # Log no banco
                try:
                    cur_log = conexao.cursor()
                    cur_log.execute(
                        "INSERT INTO log_processos (nome, fk_modelo) VALUES (%s, %s)",
                        (nome_proc, fk_modelo)
                    )
                    conexao.commit()
                    cur_log.close()
                except Exception as e:
                    registrar_log(f"Erro ao registrar {nome_proc} no log_processos: {e}")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue


# --- S3 upload ---
def send_to_s3(local_folder, bucket_name=None, s3_prefix='data/'):
    if not bucket_name:
        bucket_name = os.getenv("AWS_BUCKET_NAME")
    s3_client = boto3.client("s3",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        aws_session_token=os.getenv("AWS_SESSION_TOKEN")
    )

    if not os.path.exists(local_folder):
        registrar_log(f"Pasta {local_folder} não existe para upload.")
        return False
    
    try:
        uploaded_files = 0
        existing_files = []
        try:
            response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=s3_prefix)
            if "Contents" in response:
                existing_files = [obj["Key"].split("/")[-1] for obj in response["Contents"]]
        except Exception:
            existing_files = []

        for filename in os.listdir(local_folder):
            local_path = os.path.join(local_folder, filename)
            if filename not in existing_files and os.path.isfile(local_path):
                s3_key = f"{s3_prefix}{filename}" if s3_prefix else filename
                s3_client.upload_file(local_path, bucket_name, s3_key)
                print(f"Enviado {local_path} para s3://{bucket_name}/{s3_key}")
                uploaded_files += 1

        print(f"Upload concluído, {uploaded_files} arquivo(s) enviado(s)")
        return True
    except Exception as e:
        print(f"Erro ao enviar pasta para S3: {e}")
        return False

# --- Main ---
def main():
    print("Iniciando o monitoramento. Pressione Ctrl+C para parar.")
    
    if not os.path.exists(CAMINHO_PASTA):
        os.makedirs(CAMINHO_PASTA)
    
    inicio_captura = time.time()
    dados_coletados = []
    processos_coletados = []
    redefinir_caminho()

    try:
        conexao = mysql.connector.connect(host="localhost", user="aluno", password="sptech", database="cortex")
        processos_coletados = coletar_dados_processos()
        nomes_whitelist = check_whitelist(conexao, fk_modelo)
        matar_fora_whitelist(conexao, processos_coletados, nomes_whitelist)
        whitelist_com_matar = check_whitelist_matar(conexao, fk_modelo)
        aplicar_matar_processos(conexao, whitelist_com_matar, fk_modelo)
        conexao.close()
    except Exception as e:
        registrar_log(f"Erro ao carregar whitelist inicial: {e}")
        nomes_whitelist = set()

    while True:
        try:
            conexao = mysql.connector.connect(host="localhost", user="aluno", password="sptech", database="cortex")
            time.sleep(1)
            dados_coletados.append(coletar_dados_hardware())
            processos_coletados = coletar_dados_processos()
            matar_fora_whitelist(conexao, processos_coletados, nomes_whitelist)


            df_hardware = pd.DataFrame(dados_coletados)
            salvar_arquivo(df_hardware, CAMINHO_ARQUIVO)

            df_proc = pd.DataFrame(processos_coletados)
            salvar_arquivo(df_proc, CAMINHO_ARQUIVO_PROCESSO)

            try:
                whitelist_com_matar = check_whitelist_matar(conexao, fk_modelo)
                aplicar_matar_processos(conexao, whitelist_com_matar,fk_modelo) 
                nomes_whitelist = check_whitelist(conexao, fk_modelo)
                conexao.close()
            except Exception as e:
                registrar_log(f"Erro ao atualizar whitelist: {e}")

            if nomes_whitelist:
                verificar_whitelist_processos(processos_coletados, nomes_whitelist)

            if time.time() - inicio_captura >= DURACAO_CAPTURA:
                redefinir_caminho()
                registrar_log(f"Novo arquivo de dados criado: {NOME_ARQUIVO}")
                registrar_log(f"Novo arquivo de processos criado: {NOME_ARQUIVO_PROCESSO}")
                adicionar_a_chunks(NOME_ARQUIVO)
                adicionar_a_chunks(NOME_ARQUIVO_PROCESSO)

                try:
                    sucesso = send_to_s3(CAMINHO_PASTA, bucket_name=os.getenv("AWS_BUCKET_NAME"), s3_prefix="dados_monitoramento/")
                    if sucesso:
                        registrar_log("Upload S3 concluído com sucesso.")
                    else:
                        registrar_log("Falha no upload para S3.")
                except Exception as e:
                    registrar_log(f"Erro no upload para S3: {e}")

                inicio_captura = time.time()
                dados_coletados = []
                processos_coletados = []

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
