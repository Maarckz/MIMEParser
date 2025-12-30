import os

# ============ CONFIGURAÇÃO ============
LOG_FOLDER = os.path.join(os.path.dirname(__file__), 'logs')
DB_PATH = os.path.join(os.path.dirname(__file__), 'email_analyzer.db')

# Criar diretórios se não existirem
os.makedirs(LOG_FOLDER, exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)

# Configurações do Flask
DEBUG = True
HOST = '0.0.0.0'
PORT = 5000
