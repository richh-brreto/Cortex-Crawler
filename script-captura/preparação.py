import psutil
import mysql.connector
from datetime import datetime
import socket

# Configurações de banco
DB_CONFIG = {
    'host': 'localhost',
    'user': 'aluno',
    'password': 'sptech',
    'database': 'cortex'
}

# Identificação da máquina
nome_maquina = socket.gethostname()
ip = socket.gethostbyname(nome_maquina)
try:
    conexao = mysql.connector.connect(**DB_CONFIG)
    cursor = conexao.cursor(buffered=True)  # cursor buffered evita "Unread result found"
    
    # pega o id do modelo da máquina
    cursor.execute("SELECT id_modelo FROM modelo WHERE ip = %s AND hostname  = %s", (ip,nome_maquina))
    resultado = cursor.fetchone()
    if resultado is None:
        print(f"Máquina {nome_maquina} não cadastrada no banco.")
        exit()
    fk_modelo = resultado[0]
    
except mysql.connector.Error as e:
    print(f"Erro ao conectar ao banco: {e}")
    exit()

print("Coletando processos... pressione Ctrl+C para parar.")

try:
    while True:
        processos = [p.info['name'] for p in psutil.process_iter(['name']) if p.info['name']]
        for nome_proc in processos:
            try:
                cursor.execute(
                    "INSERT INTO whitelist (nome, fk_modelo) VALUES (%s, %s)",
                    (nome_proc, fk_modelo)
                )
                conexao.commit()
                print(f"Adicionado: {nome_proc}")
            except mysql.connector.IntegrityError:
                # já existe, ignora
                pass

except KeyboardInterrupt:
    print("\nColeta interrompida pelo usuário.")

cursor.close()
conexao.close()
