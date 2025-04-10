# Importação de bibliotecas essenciais
import numpy as np                      # Biblioteca para operações matemáticas e matrizes
import pandas as pd                    # Biblioteca para manipulação de dados em tabelas (DataFrames)
import matplotlib.pyplot as plt        # Biblioteca de visualização para gráficos
import seaborn as sns                  # Biblioteca para gráficos estatísticos (baseada em matplotlib)
import re                              # Biblioteca para uso de expressões regulares
import os                              # Biblioteca para interação com o sistema operacional
import sys                             # Biblioteca para acesso a argumentos do sistema
from sklearn.ensemble import IsolationForest     # Algoritmo de detecção de anomalias baseado em florestas de decisão
from sklearn.preprocessing import StandardScaler # Normalização dos dados
import random                          # Biblioteca para gerar números e escolhas aleatórias
import time                            # Biblioteca para manipular tempo (delays)
from tabulate import tabulate          # Biblioteca para imprimir tabelas no terminal
from colorama import init, Fore, Style # Biblioteca para impressão colorida no terminal
from IPython.display import clear_output # Limpa a saída no Jupyter Notebook

# Inicializa o colorama para resetar estilos automaticamente após cada impressão
init(autoreset=True)

# Expressões regulares e constantes para validação de dados
IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")  # Regex para validar IPs
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE"}         # Métodos HTTP permitidos
STATUS_CODES = {200, 403, 404, 500}                     # Códigos de status HTTP considerados

# Função que detecta se o script está rodando dentro do VS Code
def is_running_in_vscode():
    return "VSCODE_PID" in os.environ or any(".vscode" in arg for arg in sys.argv)

# Função que gera logs simulados e os salva em um arquivo CSV
def generate_fake_logs(filename="server_logs.csv", num_entries=1):
    # Lista de IPs simulados
    ips = [f"192.168.1.{i}" for i in range(1, 256)] + [f"10.0.0.{i}" for i in range(1, 256)]
    methods = list(HTTP_METHODS)          # Métodos possíveis
    statuses = list(STATUS_CODES)         # Status HTTP possíveis

    # Geração de dados aleatórios
    data = {
        "timestamp": pd.date_range(start=pd.Timestamp.now(), periods=num_entries, freq="min").astype(str),
        "ip": random.choices(ips, k=num_entries),
        "method": random.choices(methods, k=num_entries),
        "status": random.choices(statuses, k=num_entries),
        "response_time": np.random.uniform(0.1, 5.0, num_entries),
        "bytes_sent": np.random.randint(100, 10000, num_entries),
        "requests_per_minute": np.random.randint(1, 100, num_entries),
    }

    # Cria o DataFrame e salva no CSV
    df = pd.DataFrame(data)
    df.to_csv(filename, mode="a", header=not os.path.exists(filename), index=False)

# Função para carregar e validar os logs do arquivo
def load_logs(filename="server_logs.csv"):
    try:
        df = pd.read_csv(filename)  # Tenta ler o arquivo
    except FileNotFoundError:
        print(f"{Fore.RED}Arquivo de log não encontrado: {filename}")
        return pd.DataFrame()

    # Validação dos dados
    df = df[df["ip"].apply(lambda x: bool(IPV4_PATTERN.match(str(x))))]
    df = df[df["method"].isin(HTTP_METHODS)]
    df = df[df["status"].isin(STATUS_CODES)]
    return df

# Pré-processamento dos dados para normalização
def preprocess_logs(df):
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')  # Converte timestamp
    df.dropna(subset=["timestamp"], inplace=True)                      # Remove linhas com timestamp inválido
    df["status"] = df["status"].astype(int)

    scaler = StandardScaler()  # Instancia normalizador
    features = ["status", "response_time", "bytes_sent", "requests_per_minute"]  # Colunas para normalizar
    features = [col for col in features if df[col].nunique() > 1]  # Remove colunas com apenas um valor único

    if not features:
        return df, np.empty((df.shape[0], 0))  # Se nenhuma coluna válida, retorna array vazio

    df_scaled = scaler.fit_transform(df[features])  # Aplica normalização
    return df, df_scaled

# Detecção de anomalias com Isolation Forest
def detect_anomalies(df, df_scaled, contamination=0.01):
    if df_scaled.shape[1] == 0:
        df["anomaly_score"] = 1
        df["anomaly_raw"] = 0
        return df

    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    df["anomaly_score"] = model.fit_predict(df_scaled)         # Score binário (-1 anomalia, 1 normal)
    df["anomaly_raw"] = model.decision_function(df_scaled)     # Score contínuo (quanto mais negativo, mais anômalo)
    return df

# Classifica os acessos com base no score de anomalia
def classify_anomalies(df):
    if "anomaly_raw" not in df.columns:
        return df

    threshold_critical = np.percentile(df["anomaly_raw"], 5)      # 5% mais extremos
    threshold_suspicious = np.percentile(df["anomaly_raw"], 10)   # 10% mais extremos

    df["classification"] = "Normal"
    df.loc[df["anomaly_raw"] <= threshold_suspicious, "classification"] = "Suspeito"
    df.loc[df["anomaly_raw"] <= threshold_critical, "classification"] = "Crítico"
    return df

# Exibe os últimos logs em formato de tabela
def display_table(df):
    df_table = df.tail(10)[["timestamp", "ip", "requests_per_minute", "classification"]]
    print(tabulate(df_table, headers="keys", tablefmt="grid", showindex=False))

# Visualiza gráfico de barras com as classificações
def visualize_results(df):
    clear_output(wait=True)  # Limpa a tela a cada nova iteração
    counts = df["classification"].value_counts()

    # Garante que todas as classes estejam presentes
    for cls in ["Normal", "Suspeito", "Crítico"]:
        if cls not in counts:
            counts[cls] = 0
    counts = counts[["Normal", "Suspeito", "Crítico"]]
    colors = {"Normal": "blue", "Suspeito": "orange", "Crítico": "red"}

    plt.figure(figsize=(8, 6))
    sns.barplot(x=counts.index, y=counts.values, palette=[colors.get(c, "gray") for c in counts.index])
    plt.title("Quantidade de Acessos por Classificação")
    plt.xlabel("Classificação")
    plt.ylabel("Quantidade")
    plt.tight_layout()
    plt.show()

    # Exibe os totais no terminal com cores
    print(f"\n{Fore.BLUE}🟢 Acessos Normais: {counts.get('Normal', 0)}")
    print(f"{Fore.YELLOW}🟠 Acessos Suspeitos: {counts.get('Suspeito', 0)}")
    print(f"{Fore.RED}🔴 Acessos Críticos: {counts.get('Crítico', 0)}")

# Gráfico de linha para ver a evolução do tráfego
def visualize_traffic_trend(df):
    if len(df) < 10:
        return
    plt.figure(figsize=(10, 4))
    sns.lineplot(x=df["timestamp"].tail(50), y=df["requests_per_minute"].tail(50),
                 label="Requisições/minuto", color="green")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.title("Evolução do Tráfego (últimos 50 logs)")
    plt.xlabel("Tempo")
    plt.ylabel("REQ/min")
    plt.grid(True)
    plt.show()

# Registra eventos críticos em arquivo de log
def log_critical_events(df):
    criticals = df[df["classification"] == "Crítico"]
    if not criticals.empty:
        with open("anomalies_criticas.log", "a") as log_file:
            for _, row in criticals.iterrows():
                log_file.write(f"[{row['timestamp']}] IP: {row['ip']} - REQs/min: {row['requests_per_minute']} - STATUS: {row['status']}\n")

# Alerta visual e sonoro para cada tipo de evento
def alert_on_critical(df):
    last = df.iloc[-1]
    ip = last["ip"]
    rpm = last["requests_per_minute"]
    status = last["status"]
    cls = last["classification"]

    if cls == "Crítico":
        print("\a" + Fore.RED + f"🔴 ALERTA CRÍTICO:\n    IP: {ip} | REQs/min: {rpm} | STATUS: {status}")
    elif cls == "Suspeito":
        print(Fore.YELLOW + f"🟠 Alerta SUSPEITO:\n    IP: {ip} | REQs/min: {rpm} | STATUS: {status}")
    elif cls == "Normal":
        print(Fore.BLUE + f"🟢 Acesso NORMAL:\n    IP: {ip} | REQs/min: {rpm} | STATUS: {status}")

# Salva os últimos eventos no log histórico
def append_to_historic_log(df):
    df.tail(1)[["timestamp", "ip", "status", "requests_per_minute", "classification", "anomaly_raw"]].to_csv(
        "historic_anomaly_log.csv", mode="a", header=not os.path.exists("historic_anomaly_log.csv"), index=False
    )

# Função principal que processa os logs em tempo real (loop contínuo)
def process_logs_in_real_time():
    print("Iniciando a detecção de anomalias em tempo real...")
    if is_running_in_vscode():
        print("\n\U0001F4BB Rodando no terminal do VS Code")

    # Cria estrutura inicial vazia
    df = pd.DataFrame(columns=["timestamp", "ip", "method", "status", "response_time", "bytes_sent", "requests_per_minute"])

    while True:
        generate_fake_logs()                            # Gera novo log simulado
        new_log = load_logs("server_logs.csv").tail(1)  # Lê o último log
        df = pd.concat([df, new_log], ignore_index=True) # Adiciona ao DataFrame acumulado
        df, df_scaled = preprocess_logs(df)             # Pré-processa e normaliza
        df = detect_anomalies(df, df_scaled)            # Detecta anomalias
        df = classify_anomalies(df)                     # Classifica cada linha

        display_table(df)                               # Mostra os dados no terminal
        visualize_results(df)                           # Mostra gráfico de barras
        visualize_traffic_trend(df)                     # Mostra tendência de tráfego
        log_critical_events(df)                         # Salva eventos críticos
        alert_on_critical(df)                           # Mostra alerta em tempo real
        append_to_historic_log(df)                      # Salva em log histórico

        time.sleep(2)                                   # Espera 2 segundos antes de repetir

# Execução principal do script (só roda se não for importado como módulo)
if __name__ == "__main__":
    generate_fake_logs()             # Gera uma rodada de logs
    process_logs_in_real_time()      # Inicia o monitoramento em tempo real
