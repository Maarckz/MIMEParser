from flask import Flask, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
from config import DEBUG, HOST, PORT, LOG_FOLDER, DB_PATH
from database import EmailDatabase
from file_watcher import start_file_watcher
from api_routes import configure_routes

try:
    os.remove("email_analyzer.db")
except FileNotFoundError:
    pass

# ============ INICIALIZAÇÃO DO APP ============
app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Inicializar banco de dados
db = EmailDatabase(DB_PATH)

# ============ WEBSOCKET HANDLERS ============
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    emit('connected', {'message': 'Connected to Email Analyzer'})


@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")


@socketio.on('request_stats')
def handle_request_stats():
    """Envia estatísticas atualizadas"""
    try:
        stats = db.get_statistics()
        emit('stats_update', stats)
    except Exception as e:
        print(f"Error sending stats: {str(e)}")

# ============ CONFIGURAR ROTAS ============
# Iniciar file watcher e obter file_processor
observer, file_processor = start_file_watcher(db, socketio)

# Configurar rotas da API
configure_routes(app, db, file_processor, socketio)

# ============ INICIALIZAÇÃO ============
if __name__ == '__main__':
    print("=" * 60)
    print("📧 EMAIL ANALYZER 4.0 - MODULARIZADO")
    print("=" * 60)
    print(f"Página principal: http://{HOST}:{PORT}")
    print(f"Correlação: http://{HOST}:{PORT}/correlation")
    print(f"API Emails: http://{HOST}:{PORT}/api/emails")
    print(f"Upload EML: http://{HOST}:{PORT}/api/upload/eml")
    print(f"Database: {DB_PATH}")
    print(f"Monitoring: {LOG_FOLDER} (arquivos .eml)")
    print("=" * 60)
    print("Sistema iniciado. Aguardando emails...")
    print("=" * 60)
    
    socketio.run(app, host=HOST, port=PORT, debug=DEBUG, use_reloader=False)