import sqlite3
import zlib
import pickle
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone
import traceback
from config import DB_PATH


class EmailDatabase:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Inicializa o banco de dados com índices otimizados"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_hash TEXT UNIQUE,
                    timestamp DATETIME,
                    file_timestamp REAL,
                    file_path TEXT,
                    file_name TEXT,
                    
                    -- Metadados básicos (indexados para busca rápida)
                    message_id TEXT,
                    from_email TEXT,
                    from_domain TEXT,
                    to_email TEXT,
                    to_domain TEXT,
                    subject TEXT,
                    date DATETIME,
                    size_bytes INTEGER,
                    
                    -- Status de autenticação
                    spf_status TEXT,
                    dkim_status TEXT,
                    dmarc_status TEXT,
                    arc_status TEXT,
                    
                    -- Análise de conteúdo
                    has_attachments BOOLEAN,
                    has_urls BOOLEAN,
                    has_html BOOLEAN,
                    urls_count INTEGER,
                    attachments_count INTEGER,
                    
                    -- Tags pré-processadas
                    tags TEXT,
                    
                    -- Dados completos (comprimidos)
                    metadata BLOB,
                    authentication BLOB,
                    network_info BLOB,
                    content_analysis BLOB,
                    entities BLOB,
                    forensic_data BLOB,
                    delivery_chain BLOB,
                    security_indicators BLOB,
                    raw_data BLOB
                )
            """)
            
            # Criar índices para consultas rápidas
            indexes = [
                'CREATE INDEX IF NOT EXISTS idx_from_domain ON emails(from_domain)',
                'CREATE INDEX IF NOT EXISTS idx_to_domain ON emails(to_domain)',
                'CREATE INDEX IF NOT EXISTS idx_date ON emails(date)',
                'CREATE INDEX IF NOT EXISTS idx_spf ON emails(spf_status)',
                'CREATE INDEX IF NOT EXISTS idx_dkim ON emails(dkim_status)',
                'CREATE INDEX IF NOT EXISTS idx_dmarc ON emails(dmarc_status)',
                'CREATE INDEX IF NOT EXISTS idx_timestamp ON emails(timestamp)',
                'CREATE INDEX IF NOT EXISTS idx_size ON emails(size_bytes)',
                'CREATE INDEX IF NOT EXISTS idx_has_attachments ON emails(has_attachments)',
                'CREATE INDEX IF NOT EXISTS idx_has_urls ON emails(has_urls)'
            ]
            
            for index_sql in indexes:
                try:
                    conn.execute(index_sql)
                except:
                    pass
    
    def check_duplicate(self, file_hash: str) -> Optional[int]:
        """Verifica se um email já existe pelo hash do arquivo"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, file_name, timestamp 
                    FROM emails 
                    WHERE file_hash = ?
                """, (file_hash,))
                
                result = cursor.fetchone()
                if result:
                    return {
                        'id': result[0],
                        'file_name': result[1],
                        'timestamp': result[2]
                    }
                return None
        except Exception as e:
            print(f"[ERRO DB] Ao verificar duplicata: {str(e)}")
            return None
    
    def delete_emails(self, email_ids: List[int]) -> Dict:
        """Exclui múltiplos emails"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Verificar se os emails existem
                placeholders = ','.join('?' for _ in email_ids)
                cursor.execute(f"""
                    SELECT COUNT(*) 
                    FROM emails 
                    WHERE id IN ({placeholders})
                """, email_ids)
                
                count = cursor.fetchone()[0]
                
                if count != len(email_ids):
                    return {
                        'success': False,
                        'error': f'Alguns emails não foram encontrados ({count}/{len(email_ids)})'
                    }
                
                # Excluir os emails
                cursor.execute(f"""
                    DELETE FROM emails 
                    WHERE id IN ({placeholders})
                """, email_ids)
                
                conn.commit()
                
                deleted_count = cursor.rowcount
                
                return {
                    'success': True,
                    'deleted_count': deleted_count,
                    'message': f'{deleted_count} email(s) excluído(s) com sucesso'
                }
                
        except Exception as e:
            print(f"[ERRO DB] Ao excluir emails: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def delete_all_emails(self) -> Dict:
        """Exclui todos os emails do banco"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT COUNT(*) FROM emails")
                total = cursor.fetchone()[0]
                
                cursor.execute("DELETE FROM emails")
                conn.commit()
                
                # Resetar a sequência AUTOINCREMENT
                cursor.execute("DELETE FROM sqlite_sequence WHERE name='emails'")
                conn.commit()
                
                return {
                    'success': True,
                    'deleted_count': total,
                    'message': f'Todos os emails ({total}) foram excluídos'
                }
                
        except Exception as e:
            print(f"[ERRO DB] Ao excluir todos os emails: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def save_email(self, log_entry: Dict) -> Optional[int]:
        """Salva um email no banco de dados"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Função para comprimir dados
                def compress_data(data):
                    if not data:
                        return None
                    try:
                        # Converter bytes para strings se necessário
                        if isinstance(data, dict):
                            data = self._convert_bytes_to_strings(data)
                        return zlib.compress(pickle.dumps(data))
                    except:
                        try:
                            return pickle.dumps(data)
                        except:
                            return None
                
                raw_data = log_entry.get('raw_data', {})
                metadata = raw_data.get('metadata', {})
                analysis = log_entry.get('analysis', {})
                auth = analysis.get('authentication', {})
                content = analysis.get('content_analysis', {})
                
                # Extrair domínios de forma segura
                from_email = metadata.get('from', '')
                to_email = metadata.get('to', '')
                from_domain = from_email.split('@')[-1] if '@' in from_email else ''
                to_domain = to_email.split('@')[-1] if '@' in to_email else ''
                
                # Contar URLs de forma segura
                urls = content.get('urls', [])
                if isinstance(urls, list):
                    urls_count = len(urls)
                    has_urls = urls_count > 0
                elif isinstance(urls, (int, float)):
                    urls_count = int(urls)
                    has_urls = urls_count > 0
                else:
                    urls_count = 0
                    has_urls = False
                
                # Contar anexos de forma segura
                attachments = content.get('attachments', [])
                if isinstance(attachments, list):
                    attachments_count = len(attachments)
                    has_attachments = attachments_count > 0
                elif isinstance(attachments, (int, float)):
                    attachments_count = int(attachments)
                    has_attachments = attachments_count > 0
                else:
                    attachments_count = 0
                    has_attachments = False
                
                # Verificar se tem HTML
                html_parts = content.get('html_parts', 0)
                if isinstance(html_parts, (int, float)):
                    has_html = html_parts > 0
                else:
                    has_html = False
                
                # Processar tags
                tags = log_entry.get('tags', [])
                if isinstance(tags, list):
                    tags_str = ','.join([str(t) for t in tags[:10]])  # Limitar a 10 tags
                else:
                    tags_str = ''
                
                # Obter status de autenticação de forma segura
                def get_auth_status(auth_data, protocol):
                    if not isinstance(auth_data, dict):
                        return 'none'
                    proto_data = auth_data.get(protocol, {})
                    if not isinstance(proto_data, dict):
                        return 'none'
                    status = proto_data.get('status', 'none')
                    
                    # Para ARC, verificar se há detalhes mesmo com status none
                    if protocol == 'arc' and status == 'none':
                        details = proto_data.get('details', [])
                        if isinstance(details, list) and len(details) > 0:
                            for detail in details:
                                if isinstance(detail, dict):
                                    header = detail.get('header', '').lower()
                                    value = detail.get('value', '').lower()
                                    if 'arc-' in header or 'arc-' in value:
                                        return 'present'
                    return status
                
                spf_status = get_auth_status(auth, 'spf')
                dkim_status = get_auth_status(auth, 'dkim')
                dmarc_status = get_auth_status(auth, 'dmarc')
                arc_status = get_auth_status(auth, 'arc')
                
                # Garantir que values sejam do tipo correto para SQL
                cursor.execute("""
                    INSERT OR REPLACE INTO emails (
                        file_hash, timestamp, file_timestamp, file_path, file_name,
                        message_id, from_email, from_domain, to_email, to_domain,
                        subject, date, size_bytes,
                        spf_status, dkim_status, dmarc_status, arc_status,
                        has_attachments, has_urls, has_html, urls_count, attachments_count,
                        tags,
                        metadata, authentication, network_info, content_analysis,
                        entities, forensic_data, delivery_chain, security_indicators, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    log_entry.get('file_hash', '')[:255],
                    log_entry.get('timestamp', datetime.now(timezone.utc).isoformat()),
                    float(log_entry.get('file_timestamp', 0)),
                    log_entry.get('file_path', '')[:500],
                    log_entry.get('file_name', '')[:255],
                    
                    metadata.get('message_id', '')[:255],
                    from_email[:255],
                    from_domain[:100],
                    to_email[:255],
                    to_domain[:100],
                    metadata.get('subject', '')[:500],
                    metadata.get('date', ''),
                    int(metadata.get('size_bytes', 0)),
                    
                    spf_status[:10],
                    dkim_status[:10],
                    dmarc_status[:10],
                    arc_status[:10],
                    
                    1 if has_attachments else 0,
                    1 if has_urls else 0,
                    1 if has_html else 0,
                    int(urls_count),
                    int(attachments_count),
                    
                    tags_str[:500],
                    
                    compress_data(metadata),
                    compress_data(auth),
                    compress_data(analysis.get('network_analysis', {})),
                    compress_data(content),
                    compress_data(analysis.get('entities', {})),
                    compress_data(analysis.get('forensic', {})),
                    compress_data(log_entry.get('normalized_data', {}).get('delivery_info', {})),
                    compress_data(analysis.get('security_indicators', {})),
                    compress_data(raw_data)
                ))
                
                email_id = cursor.lastrowid
                conn.commit()
                print(f"[DB SUCESSO] Email salvo com ID: {email_id}, From: {from_email}")
                return email_id
                
        except Exception as e:
            print(f"[ERRO DB] Ao salvar email: {str(e)}")
            traceback.print_exc()
            return None
    
    def _convert_bytes_to_strings(self, data):
        """Converte bytes para strings em um dicionário"""
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                result[key] = self._convert_bytes_to_strings(value)
            return result
        elif isinstance(data, list):
            return [self._convert_bytes_to_strings(item) for item in data]
        elif isinstance(data, bytes):
            try:
                return data.decode('utf-8', errors='ignore')
            except:
                return str(data)
        else:
            return data
    
    def get_email(self, email_id: int) -> Optional[Dict]:
        """Recupera um email do banco de dados"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT * FROM emails WHERE id = ?
                """, (email_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Descomprimir dados
                def decompress_data(blob):
                    if blob:
                        try:
                            data = pickle.loads(zlib.decompress(blob))
                            return self._convert_bytes_to_strings(data)
                        except:
                            try:
                                data = pickle.loads(blob)
                                return self._convert_bytes_to_strings(data)
                            except:
                                return {}
                    return {}
                
                # Converter bytes para strings nos campos de texto
                metadata = decompress_data(row['metadata'])
                authentication = decompress_data(row['authentication'])
                network_info = decompress_data(row['network_info'])
                content_analysis = decompress_data(row['content_analysis'])
                entities = decompress_data(row['entities'])
                forensic = decompress_data(row['forensic_data'])
                delivery_chain = decompress_data(row['delivery_chain'])
                security_indicators = decompress_data(row['security_indicators'])
                raw_data = decompress_data(row['raw_data'])
                
                # Processar tags
                tags = []
                if row['tags']:
                    tags = [tag.strip() for tag in row['tags'].split(',') if tag.strip()]
                
                return {
                    'id': row['id'],
                    'timestamp': row['timestamp'],
                    'file_name': row['file_name'],
                    'file_path': row['file_path'],
                    'message_id': row['message_id'],
                    'from_email': row['from_email'],
                    'from_domain': row['from_domain'],
                    'to_email': row['to_email'],
                    'to_domain': row['to_domain'],
                    'subject': row['subject'],
                    'date': row['date'],
                    'size_bytes': row['size_bytes'],
                    'spf_status': row['spf_status'],
                    'dkim_status': row['dkim_status'],
                    'dmarc_status': row['dmarc_status'],
                    'arc_status': row['arc_status'],
                    'has_attachments': bool(row['has_attachments']),
                    'has_urls': bool(row['has_urls']),
                    'has_html': bool(row['has_html']),
                    'urls_count': row['urls_count'],
                    'attachments_count': row['attachments_count'],
                    'tags': tags,
                    'metadata': metadata,
                    'analysis': {
                        'authentication': authentication,
                        'network_analysis': network_info,
                        'content_analysis': content_analysis,
                        'entities': entities,
                        'forensic': forensic,
                        'security_indicators': security_indicators
                    },
                    'normalized_data': {
                        'delivery_info': delivery_chain
                    },
                    'raw_data': raw_data
                }
        except Exception as e:
            print(f"[ERRO DB] Ao recuperar email {email_id}: {str(e)}")
            traceback.print_exc()
            return None
    
    def get_emails_paginated(self, page: int = 1, per_page: int = 50, 
                           filters: Dict = None) -> Tuple[List[Dict], Dict]:
        """Recupera emails com paginação e filtros"""
        filters = filters or {}
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Construir query base
                query = """
                    SELECT id, timestamp, file_name, message_id, from_email, from_domain, 
                           to_email, to_domain, subject, date, size_bytes, spf_status, dkim_status, 
                           dmarc_status, arc_status, has_attachments, has_urls, has_html, 
                           urls_count, attachments_count, tags 
                    FROM emails 
                    WHERE 1=1
                """
                params = []
                
                # Aplicar filtros
                if filters.get('search'):
                    search = f"%{filters['search']}%"
                    query += " AND (from_email LIKE ? OR to_email LIKE ? OR subject LIKE ? OR tags LIKE ? OR message_id LIKE ?)"
                    params.extend([search, search, search, search, search])
                
                if filters.get('spf_status'):
                    query += " AND spf_status = ?"
                    params.append(filters['spf_status'])
                
                if filters.get('dkim_status'):
                    query += " AND dkim_status = ?"
                    params.append(filters['dkim_status'])
                
                if filters.get('dmarc_status'):
                    query += " AND dmarc_status = ?"
                    params.append(filters['dmarc_status'])
                
                if filters.get('arc_status'):
                    query += " AND arc_status = ?"
                    params.append(filters['arc_status'])
                
                if filters.get('from_domain'):
                    query += " AND from_domain = ?"
                    params.append(filters['from_domain'])
                
                if filters.get('has_attachments'):
                    query += " AND has_attachments = 1"
                
                if filters.get('has_urls'):
                    query += " AND has_urls = 1"
                
                # Ordenação
                sort_field = filters.get('sort', 'timestamp_desc')
                if sort_field == 'date_desc':
                    query += " ORDER BY date DESC"
                elif sort_field == 'date_asc':
                    query += " ORDER BY date ASC"
                elif sort_field == 'from_email':
                    query += " ORDER BY from_email"
                elif sort_field == 'subject':
                    query += " ORDER BY subject"
                else:  # timestamp_desc padrão
                    query += " ORDER BY timestamp DESC"
                
                # Contar total - CORRIGIDO
                count_query = "SELECT COUNT(*) FROM emails WHERE 1=1"
                count_params = []
                
                # Aplicar os mesmos filtros na count query
                if filters.get('search'):
                    search = f"%{filters['search']}%"
                    count_query += " AND (from_email LIKE ? OR to_email LIKE ? OR subject LIKE ? OR tags LIKE ? OR message_id LIKE ?)"
                    count_params.extend([search, search, search, search, search])
                
                if filters.get('spf_status'):
                    count_query += " AND spf_status = ?"
                    count_params.append(filters['spf_status'])
                
                if filters.get('dkim_status'):
                    count_query += " AND dkim_status = ?"
                    count_params.append(filters['dkim_status'])
                
                if filters.get('dmarc_status'):
                    count_query += " AND dmarc_status = ?"
                    count_params.append(filters['dmarc_status'])
                
                if filters.get('arc_status'):
                    count_query += " AND arc_status = ?"
                    count_params.append(filters['arc_status'])
                
                if filters.get('from_domain'):
                    count_query += " AND from_domain = ?"
                    count_params.append(filters['from_domain'])
                
                if filters.get('has_attachments'):
                    count_query += " AND has_attachments = 1"
                
                if filters.get('has_urls'):
                    count_query += " AND has_urls = 1"
                
                cursor.execute(count_query, count_params)
                result = cursor.fetchone()
                total = result[0] if result else 0
                
                # Paginação
                offset = (page - 1) * per_page
                query += " LIMIT ? OFFSET ?"
                params.extend([per_page, offset])
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                # Converter para dicionários
                emails = []
                for row in rows:
                    emails.append({
                        'id': row['id'],
                        'timestamp': row['timestamp'],
                        'file_name': row['file_name'],
                        'message_id': row['message_id'],
                        'from_email': row['from_email'],
                        'from_domain': row['from_domain'],
                        'to_email': row['to_email'],
                        'to_domain': row['to_domain'],
                        'subject': row['subject'],
                        'date': row['date'],
                        'size_bytes': row['size_bytes'],
                        'spf_status': row['spf_status'],
                        'dkim_status': row['dkim_status'],
                        'dmarc_status': row['dmarc_status'],
                        'arc_status': row['arc_status'],
                        'has_attachments': bool(row['has_attachments']),
                        'has_urls': bool(row['has_urls']),
                        'has_html': bool(row['has_html']),
                        'urls_count': row['urls_count'],
                        'attachments_count': row['attachments_count'],
                        'tags': row['tags'].split(',') if row['tags'] else []
                    })
                
                pages = (total + per_page - 1) // per_page if per_page > 0 else 0
                
                pagination = {
                    'page': page,
                    'per_page': per_page,
                    'total': total,
                    'pages': pages
                }
                
                return emails, pagination
        except Exception as e:
            print(f"[ERRO DB] Ao listar emails: {str(e)}")
            traceback.print_exc()
            return [], {'page': 1, 'per_page': 50, 'total': 0, 'pages': 0}
    
    def get_statistics(self) -> Dict:
        """Retorna estatísticas agregadas"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Estatísticas básicas
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total,
                        COUNT(DISTINCT from_domain) as unique_domains,
                        COALESCE(SUM(CASE WHEN has_attachments = 1 THEN 1 ELSE 0 END), 0) as emails_with_attachments,
                        COALESCE(SUM(CASE WHEN has_urls = 1 THEN 1 ELSE 0 END), 0) as emails_with_urls
                    FROM emails
                """)
                row = cursor.fetchone()
                if row:
                    stats['total_emails'] = row[0]
                    stats['unique_domains'] = row[1]
                    stats['emails_with_attachments'] = row[2]
                    stats['emails_with_urls'] = row[3]
                
                # Status de autenticação
                cursor.execute("""
                    SELECT 
                        COALESCE(SUM(CASE WHEN spf_status = 'pass' THEN 1 ELSE 0 END), 0) as spf_pass,
                        COALESCE(SUM(CASE WHEN spf_status = 'fail' THEN 1 ELSE 0 END), 0) as spf_fail,
                        COALESCE(SUM(CASE WHEN spf_status = 'none' THEN 1 ELSE 0 END), 0) as spf_none,
                        COALESCE(SUM(CASE WHEN spf_status = 'present' THEN 1 ELSE 0 END), 0) as spf_present,
                        COALESCE(SUM(CASE WHEN dkim_status = 'pass' THEN 1 ELSE 0 END), 0) as dkim_pass,
                        COALESCE(SUM(CASE WHEN dkim_status = 'fail' THEN 1 ELSE 0 END), 0) as dkim_fail,
                        COALESCE(SUM(CASE WHEN dkim_status = 'none' THEN 1 ELSE 0 END), 0) as dkim_none,
                        COALESCE(SUM(CASE WHEN dkim_status = 'present' THEN 1 ELSE 0 END), 0) as dkim_present,
                        COALESCE(SUM(CASE WHEN dmarc_status = 'pass' THEN 1 ELSE 0 END), 0) as dmarc_pass,
                        COALESCE(SUM(CASE WHEN dmarc_status = 'fail' THEN 1 ELSE 0 END), 0) as dmarc_fail,
                        COALESCE(SUM(CASE WHEN dmarc_status = 'none' THEN 1 ELSE 0 END), 0) as dmarc_none,
                        COALESCE(SUM(CASE WHEN dmarc_status = 'present' THEN 1 ELSE 0 END), 0) as dmarc_present,
                        COALESCE(SUM(CASE WHEN arc_status = 'pass' THEN 1 ELSE 0 END), 0) as arc_pass,
                        COALESCE(SUM(CASE WHEN arc_status = 'fail' THEN 1 ELSE 0 END), 0) as arc_fail,
                        COALESCE(SUM(CASE WHEN arc_status = 'none' THEN 1 ELSE 0 END), 0) as arc_none,
                        COALESCE(SUM(CASE WHEN arc_status = 'present' THEN 1 ELSE 0 END), 0) as arc_present,
                        COALESCE(SUM(attachments_count), 0) as total_attachments,
                        COALESCE(SUM(urls_count), 0) as total_urls,
                        COALESCE(AVG(size_bytes), 0) as avg_size
                    FROM emails
                """)
                row = cursor.fetchone()
                if row:
                    stats.update({
                        'spf_pass': row[0],
                        'spf_fail': row[1],
                        'spf_none': row[2],
                        'spf_present': row[3],
                        'dkim_pass': row[4],
                        'dkim_fail': row[5],
                        'dkim_none': row[6],
                        'dkim_present': row[7],
                        'dmarc_pass': row[8],
                        'dmarc_fail': row[9],
                        'dmarc_none': row[10],
                        'dmarc_present': row[11],
                        'arc_pass': row[12],
                        'arc_fail': row[13],
                        'arc_none': row[14],
                        'arc_present': row[15],
                        'total_attachments': row[16],
                        'total_urls': row[17],
                        'avg_size': row[18]
                    })
                
                # Domínios mais frequentes
                cursor.execute("""
                    SELECT from_domain, COUNT(*) as count 
                    FROM emails 
                    WHERE from_domain != '' 
                    GROUP BY from_domain 
                    ORDER BY count DESC 
                    LIMIT 10
                """)
                stats['top_domains'] = [{'domain': row[0], 'count': row[1]} for row in cursor.fetchall()]
                
                # Último email processado
                cursor.execute("SELECT MAX(timestamp) FROM emails")
                last_update = cursor.fetchone()
                stats['last_update'] = last_update[0] if last_update and last_update[0] else datetime.now(timezone.utc).isoformat()
                
                return stats
        except Exception as e:
            print(f"[ERRO DB] Ao buscar estatísticas: {str(e)}")
            traceback.print_exc()
            return {
                'total_emails': 0,
                'unique_domains': 0,
                'emails_with_attachments': 0,
                'emails_with_urls': 0,
                'spf_pass': 0, 'spf_fail': 0, 'spf_none': 0, 'spf_present': 0,
                'dkim_pass': 0, 'dkim_fail': 0, 'dkim_none': 0, 'dkim_present': 0,
                'dmarc_pass': 0, 'dmarc_fail': 0, 'dmarc_none': 0, 'dmarc_present': 0,
                'arc_pass': 0, 'arc_fail': 0, 'arc_none': 0, 'arc_present': 0,
                'total_attachments': 0,
                'total_urls': 0,
                'avg_size': 0,
                'top_domains': [],
                'last_update': datetime.now(timezone.utc).isoformat()
            }
    
    def get_correlation_data(self, days: int = 7) -> Dict:
        """Retorna dados para análise de correlação"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                correlation = {}
                
                # Padrões por remetente
                cursor.execute(f"""
                    SELECT 
                        from_domain,
                        COUNT(*) as total_emails,
                        AVG(size_bytes) as avg_size,
                        ROUND(SUM(CASE WHEN spf_status = 'pass' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 1) as spf_pass_rate,
                        ROUND(SUM(CASE WHEN dkim_status = 'pass' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 1) as dkim_pass_rate,
                        SUM(urls_count) as total_urls,
                        SUM(attachments_count) as total_attachments,
                        MAX(timestamp) as last_email
                    FROM emails
                    WHERE from_domain != '' AND from_domain IS NOT NULL
                          AND timestamp >= datetime('now', '-{days} days')
                    GROUP BY from_domain
                    HAVING total_emails >= 1
                    ORDER BY total_emails DESC
                    LIMIT 20
                """)
                correlation['sender_patterns'] = []
                for row in cursor.fetchall():
                    correlation['sender_patterns'].append({
                        'domain': row[0],
                        'total_emails': row[1],
                        'avg_size': float(row[2] or 0),
                        'spf_pass_rate': float(row[3] or 0),
                        'dkim_pass_rate': float(row[4] or 0),
                        'total_urls': row[5] or 0,
                        'total_attachments': row[6] or 0,
                        'last_email': row[7]
                    })
                
                # Sequências temporais
                cursor.execute(f"""
                    SELECT 
                        strftime('%H', timestamp) as hour,
                        COUNT(*) as count
                    FROM emails
                    WHERE timestamp >= datetime('now', '-{days} days')
                    GROUP BY hour
                    ORDER BY hour
                """)
                correlation['hourly_patterns'] = [{'hour': row[0], 'count': row[1]} for row in cursor.fetchall()]
                
                # Relações entre domínios
                cursor.execute(f"""
                    SELECT 
                        from_domain,
                        to_domain,
                        COUNT(*) as frequency,
                        ROUND(SUM(CASE WHEN spf_status = 'pass' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 1) as spf_rate,
                        ROUND(SUM(CASE WHEN dkim_status = 'pass' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 1) as dkim_rate,
                        MAX(timestamp) as last_email
                    FROM emails
                    WHERE from_domain != '' AND to_domain != '' 
                          AND from_domain IS NOT NULL AND to_domain IS NOT NULL
                          AND timestamp >= datetime('now', '-{days} days')
                    GROUP BY from_domain, to_domain
                    HAVING frequency >= 1
                    ORDER BY frequency DESC
                    LIMIT 15
                """)
                correlation['domain_relations'] = []
                for row in cursor.fetchall():
                    correlation['domain_relations'].append({
                        'from': row[0],
                        'to': row[1],
                        'frequency': row[2],
                        'spf_rate': float(row[3] or 0),
                        'dkim_rate': float(row[4] or 0),
                        'last_email': row[5]
                    })
                
                return correlation
        except Exception as e:
            print(f"[ERRO DB] Ao buscar correlação: {str(e)}")
            traceback.print_exc()
            return {
                'sender_patterns': [],
                'hourly_patterns': [],
                'domain_relations': []
            }