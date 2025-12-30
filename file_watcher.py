import os
import time
import threading
import hashlib
from datetime import datetime, timezone
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import traceback
from typing import Dict  # ADICIONAR ESTE IMPORT

from config import LOG_FOLDER
from database import EmailDatabase
from analyzer import MIMEForensicExtractor, EnhancedEmailAnalyzer, extract_tags


# ============ PROCESSAMENTO DE ARQUIVOS ============
class FileProcessor:
    def __init__(self, db: EmailDatabase, socketio):
        self.db = db
        self.socketio = socketio
        self.analyzer = EnhancedEmailAnalyzer()
        self.processed_files = set()
    
    def check_duplicate(self, file_content: bytes) -> Dict:
        """Verifica se o email já existe no banco"""
        file_hash = hashlib.sha256(file_content).hexdigest()
        return self.db.check_duplicate(file_hash)
    
    def process_eml_file(self, file_path: str, skip_duplicate: bool = True):
        """Processa um arquivo .eml usando o MIMEForensicExtractor"""
        try:
            print(f"[PROCESSANDO EML] Arquivo: {file_path}")
            
            # Verificar se já foi processado recentemente
            file_stat = os.stat(file_path)
            file_key = f"{file_path}:{file_stat.st_mtime}:{file_stat.st_size}"
            
            if file_key in self.processed_files:
                print(f"[SKIP] Arquivo EML já processado: {file_path}")
                return {
                    'success': False,
                    'error': 'Arquivo já processado',
                    'skip': True
                }
            
            # Carregar e analisar o arquivo .eml
            with open(file_path, 'rb') as f:
                email_content = f.read()
            
            # Verificar duplicata
            if skip_duplicate:
                duplicate_info = self.check_duplicate(email_content)
                if duplicate_info:
                    print(f"[DUPLICATA] Email já existe no banco. ID: {duplicate_info['id']}, Nome: {duplicate_info['file_name']}")
                    return {
                        'success': False,
                        'error': 'Email duplicado',
                        'duplicate': duplicate_info,
                        'skip': True
                    }
            
            extractor = MIMEForensicExtractor(email_content)
            mime_results = extractor.analyze()
            
            print(f"[DADOS EML CARREGADOS] De: {mime_results.get('metadata', {}).get('from', 'Unknown')}")
            
            # Converter resultados do MIME para formato compatível
            data = {
                'metadata': mime_results['metadata'],
                'authentication': mime_results['authentication'],
                'content_analysis': mime_results['content_analysis'],
                'network_analysis': mime_results['network_analysis'],
                'extracted_entities': mime_results['extracted_entities'],
                'forensic_hashes': mime_results['forensic_hashes'],
                'delivery_chain': mime_results['delivery_chain']
            }
            
            # Analisar email usando o EnhancedEmailAnalyzer
            analysis = self.analyzer.analyze_email(data)
            
            # Extrair tags
            tags = extract_tags(data)
            
            # Criar entrada de log
            metadata = data.get('metadata', {})
            
            log_entry = {
                'file_hash': hashlib.sha256(email_content).hexdigest(),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'file_timestamp': file_stat.st_mtime,
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'analysis': analysis,
                'raw_data': data,
                'tags': tags,
                'normalized_data': {
                    'delivery_info': mime_results.get('delivery_chain', {})
                }
            }
            
            # Salvar no banco de dados
            email_id = self.db.save_email(log_entry)
            
            if email_id:
                # Atualizar cache
                self.processed_files.add(file_key)
                
                # Emitir evento via socketio
                self.socketio.emit('new_email', {
                    'id': email_id,
                    'from': metadata.get('from', ''),
                    'subject': metadata.get('subject', ''),
                    'timestamp': log_entry['timestamp'],
                    'total_emails': self.db.get_statistics()['total_emails']
                })
                
                print(f"[SUCESSO EML] Processado: {file_path} -> ID: {email_id}")
                return {
                    'success': True,
                    'email_id': email_id,
                    'file_path': file_path,
                    'metadata': metadata
                }
            else:
                print(f"[ERRO EML] Falha ao salvar no banco: {file_path}")
                return {
                    'success': False,
                    'error': 'Falha ao salvar no banco de dados',
                    'skip': False
                }
            
        except Exception as e:
            print(f"[ERRO EML] Ao processar {file_path}: {str(e)}")
            traceback.print_exc()
            return {
                'success': False,
                'error': str(e),
                'skip': False
            }
    
    def process_upload(self, file_path: str, skip_duplicate: bool = True):
        """Processa um upload de arquivo .eml"""
        result = self.process_eml_file(file_path, skip_duplicate)
        
        if result.get('success'):
            # Emitir estatísticas atualizadas
            stats = self.db.get_statistics()
            self.socketio.emit('stats_update', stats)
        
        return result


# ============ FILE WATCHER ============
class OptimizedFileHandler(FileSystemEventHandler):
    def __init__(self, file_processor: FileProcessor):
        self.file_processor = file_processor
        self.debounce_timer = {}
        self.processing_queue = []
        self.processing = False
        self.lock = threading.Lock()
    
    def on_created(self, event):
        if not event.is_directory:
            self.debounce_process(event.src_path)
    
    def on_modified(self, event):
        if not event.is_directory:
            self.debounce_process(event.src_path)
    
    def debounce_process(self, file_path):
        """Debounce para evitar processamento múltiplo"""
        if not file_path.endswith('.eml'):
            return
        
        current_time = time.time()
        
        with self.lock:
            if file_path in self.debounce_timer:
                if current_time - self.debounce_timer[file_path] < 2.0:
                    return
            
            self.debounce_timer[file_path] = current_time
            
            # Adicionar à fila
            if file_path not in self.processing_queue:
                self.processing_queue.append(file_path)
            
            # Iniciar processamento se não estiver rodando
            if not self.processing:
                self.start_processing()
    
    def start_processing(self):
        """Inicia processamento da fila"""
        if self.processing:
            return
        
        self.processing = True
        
        def process_queue():
            while True:
                with self.lock:
                    if not self.processing_queue:
                        self.processing = False
                        break
                    
                    file_path = self.processing_queue.pop(0)
                
                try:
                    result = self.file_processor.process_eml_file(file_path)
                    if result.get('success'):
                        # Emitir estatísticas atualizadas
                        stats = self.file_processor.db.get_statistics()
                        self.file_processor.socketio.emit('stats_update', stats)
                    
                    time.sleep(0.1)  # Pequena pausa entre arquivos
                except Exception as e:
                    print(f"[ERRO Fila] {file_path}: {str(e)}")
            
            self.processing = False
        
        # Processar em thread separada
        threading.Thread(target=process_queue, daemon=True).start()


def start_file_watcher(db: EmailDatabase, socketio):
    """Inicia monitoramento de arquivos"""
    file_processor = FileProcessor(db, socketio)
    event_handler = OptimizedFileHandler(file_processor)
    observer = Observer()
    observer.schedule(event_handler, LOG_FOLDER, recursive=True)
    observer.start()
    
    # Processar arquivos existentes em batch
    def process_existing_files():
        print(f"[INICIANDO] Processamento de arquivos existentes em: {LOG_FOLDER}")
        
        eml_files = []
        for root, _, files in os.walk(LOG_FOLDER):
            for file in files:
                if file.endswith('.eml'):
                    eml_files.append(os.path.join(root, file))
        
        print(f"[ENCONTRADOS] {len(eml_files)} arquivos .eml")
        
        # Processar em batches para não sobrecarregar
        batch_size = 10
        total_processed = 0
        total_duplicates = 0
        
        for i in range(0, len(eml_files), batch_size):
            batch = eml_files[i:i+batch_size]
            print(f"[BATCH] Processando arquivos {i+1} a {min(i+batch_size, len(eml_files))}")
            
            for file_path in batch:
                result = file_processor.process_eml_file(file_path)
                if result.get('success'):
                    total_processed += 1
                elif result.get('duplicate'):
                    total_duplicates += 1
            
            if i + batch_size < len(eml_files):
                time.sleep(0.5)  # Pausa entre batches
        
        print(f"[PROCESSAMENTO COMPLETO] {total_processed} arquivos processados, {total_duplicates} duplicatas ignoradas")
        
        # Emitir estatísticas finais
        stats = db.get_statistics()
        socketio.emit('stats_update', stats)
    
    # Iniciar processamento em thread separada
    threading.Thread(target=process_existing_files, daemon=True).start()
    
    print(f"[WATCHER] Monitorando: {LOG_FOLDER} para arquivos .eml")
    return observer, file_processor
