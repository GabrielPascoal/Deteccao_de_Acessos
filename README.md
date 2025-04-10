# Deteccao_de_Acessos
 O sistema simula logs de acesso, processa e analisa os dados com técnicas de aprendizado de máquina para identificar padrões anômalos. Ele classifica os acessos como *Normal, **Suspeito* ou *Crítico*, gerando alertas em tempo real e registrando eventos relevantes.

## Funcionalidades
- Geração automática de logs de acesso
- Pré-processamento e validação dos dados
- Detecção de anomalias com Isolation Forest
- Classificação em Normal, Suspeito e Crítico
- Visualização de resultados com gráficos e tabelas
- Log de eventos críticos
- Alertas no terminal em tempo real
- Registro histórico de anomalias

## Instruções de Instalação
1. Clone o repositório:
   ```bash
   git clone https://github.com/gabrielpascoal/deteccao_de_acessos.git
   cd deteccao_de_acessos

2. Crie um Ambiente Virtual:
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows

3. Instalar as Dependências:
   pip install -r requirements.txt

Execute o projeto
python seu_script.py 

## Autores
Gabriel Guilherme Pascoal
Kaue Borges Nascimento
