from flask import jsonify, request, render_template, send_file
import os
import traceback
from datetime import datetime
import sqlite3
import tempfile
import json
import pickle
import zlib

from config import LOG_FOLDER, DB_PATH
from database import EmailDatabase
from analyzer import MIMEForensicExtractor, EnhancedEmailAnalyzer, extract_tags
import hashlib

# Tentar importar as ferramentas de segurança
try:
    from security_tools import SecurityAnalyzer, EmailRenderer
    SECURITY_TOOLS_AVAILABLE = True
except ImportError:
    # Criar classes placeholder se não disponíveis
    class SecurityAnalyzer:
        @staticmethod
        def dns_lookup(domain):
            return {'domain': domain, 'error': 'DNS module not available', 'configure': True}
        
        @staticmethod
        def whois_lookup(domain):
            return {'domain': domain, 'error': 'WHOIS module not available', 'configure': True}
        
        @staticmethod
        def check_virustotal_file(file_hash):
            return {'error': 'VirusTotal API key not configured', 'configure': True}
        
        @staticmethod
        def check_virustotal_url(url):
            return {'error': 'VirusTotal API key not configured', 'configure': True}
        
        @staticmethod
        def analyze_pdf(file_path, file_hash):
            return {'file_path': file_path, 'file_hash': file_hash, 'error': 'PDF module not available', 'configure': True}
        
        @staticmethod
        def reverse_dns_lookup(ip):
            return {'ip': ip, 'error': 'rDNS lookup failed'}
        
        @staticmethod
        def analyze_binary_file(file_path, file_hash):
            return {'file_path': file_path, 'file_hash': file_hash, 'error': 'Binary analysis not available'}
    
    class EmailRenderer:
        @staticmethod
        def render_email_safely(email_data):
            return {
                'headers': {},
                'body_preview': {},
                'attachments_info': [],
                'is_safe': False,
                'warnings': ['Security tools not available']
            }
    
    SECURITY_TOOLS_AVAILABLE = False
    print("[AVISO] Usando versão simplificada das ferramentas de segurança")


def configure_routes(app, db, file_processor, socketio):
    """Configura todas as rotas da API"""
    
    @app.route('/')
    def index():
        """Página principal"""
        return render_template('logs.html')
    
    @app.route('/log/<int:email_id>')
    def log_detail(email_id):
        """Detalhes do log"""
        return render_template('log_detail.html', email_id=email_id)
    
    @app.route('/correlation')
    def correlation_view():
        """Visualização de correlação"""
        return render_template('correlation.html')
    
    @app.route('/upload')
    def upload_page():
        """Página de upload de emails"""
        return render_template('upload.html')
    
    @app.route('/api/emails')
    def get_emails():
        """API para listar emails com paginação"""
        try:
            page = int(request.args.get('page', 1))
            per_page = min(int(request.args.get('per_page', 50)), 100)
            
            filters = {
                'search': request.args.get('search', ''),
                'spf_status': request.args.get('spf_status', ''),
                'dkim_status': request.args.get('dkim_status', ''),
                'dmarc_status': request.args.get('dmarc_status', ''),
                'arc_status': request.args.get('arc_status', ''),
                'from_domain': request.args.get('from_domain', ''),
                'has_attachments': request.args.get('has_attachments') == 'true',
                'has_urls': request.args.get('has_urls') == 'true',
                'sort': request.args.get('sort', 'timestamp_desc')
            }
            
            emails, pagination = db.get_emails_paginated(page, per_page, filters)
            
            return jsonify({
                'success': True,
                'emails': emails,
                'pagination': pagination
            })
            
        except Exception as e:
            print(f"[ERRO API] /api/emails: {str(e)}")
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e),
                'emails': [],
                'pagination': {'page': 1, 'per_page': 50, 'total': 0, 'pages': 0}
            }), 500
    
    @app.route('/api/emails/<int:email_id>')
    def get_email_detail(email_id):
        """API para detalhes completos do email"""
        try:
            email = db.get_email(email_id)
            if not email:
                return jsonify({'success': False, 'error': 'Email not found'}), 404
            
            # Função auxiliar para garantir serialização JSON
            def make_json_serializable(obj):
                if isinstance(obj, dict):
                    return {k: make_json_serializable(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [make_json_serializable(item) for item in obj]
                elif isinstance(obj, (str, int, float, bool, type(None))):
                    return obj
                else:
                    return str(obj)
            
            # Tornar o email serializável em JSON
            email_serializable = make_json_serializable(email)
            
            return jsonify({
                'success': True,
                'email': email_serializable
            })
            
        except Exception as e:
            print(f"[ERRO API] /api/emails/{email_id}: {str(e)}")
            traceback.print_exc()
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # ============ NOVAS ROTAS DE ANÁLISE DE SEGURANÇA ============
    
    @app.route('/api/emails/<int:email_id>/security')
    def get_email_security(email_id):
        """API para análises de segurança do email"""
        try:
            email = db.get_email(email_id)
            if not email:
                return jsonify({'success': False, 'error': 'Email not found'}), 404
            
            # Inicializar analisador de segurança
            security_analyzer = SecurityAnalyzer()
            email_renderer = EmailRenderer()
            
            results = {
                'email_id': email_id,
                'dns_lookups': {},
                'whois_lookups': {},
                'virustotal_checks': {},
                'binary_analysis': {},
                'email_preview': {},
                'attachment_details': [],
                'tools_available': SECURITY_TOOLS_AVAILABLE
            }
            
            metadata = email.get('metadata', {})
            analysis = email.get('analysis', {})
            content = analysis.get('content_analysis', {})
            network = analysis.get('network_analysis', {})
            
            # Obter domínio do remetente para DNS/WHOIS
            from_email = metadata.get('from', '')
            if '@' in from_email:
                domain = from_email.split('@')[-1]
                
                # DNS lookup para domínio do remetente
                results['dns_lookups'][domain] = security_analyzer.dns_lookup(domain)
                
                # WHOIS lookup para domínio do remetente
                results['whois_lookups'][domain] = security_analyzer.whois_lookup(domain)
            
            # Verificar IP de origem
            originating_ip = network.get('originating_ip')
            if originating_ip:
                # rDNS lookup para IP de origem
                results['reverse_dns'] = security_analyzer.reverse_dns_lookup(originating_ip)
            
            # Verificar anexos no VirusTotal
            attachments = content.get('attachments', [])
            if isinstance(attachments, list):
                for att in attachments:
                    if isinstance(att, dict):
                        file_hash = att.get('sha256')
                        if file_hash:
                            # VirusTotal check
                            vt_result = security_analyzer.check_virustotal_file(file_hash)
                            results['virustotal_checks'][file_hash] = vt_result
                            
                            # Adicionar detalhes do anexo
                            att_details = att.copy()
                            att_details['virustotal'] = vt_result
                            results['attachment_details'].append(att_details)
            
            # Renderizar preview seguro do email
            results['email_preview'] = email_renderer.render_email_safely(email)
            
            return jsonify({
                'success': True,
                'security_analysis': results
            })
            
        except Exception as e:
            print(f"[ERRO API] /api/emails/{email_id}/security: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/security/dns/<domain>')
    def get_dns_lookup(domain):
        """API para lookup DNS de um domínio"""
        try:
            security_analyzer = SecurityAnalyzer()
            results = security_analyzer.dns_lookup(domain)
            
            return jsonify({
                'success': True,
                'domain': domain,
                'dns_results': results
            })
            
        except Exception as e:
            print(f"[ERRO API] /api/security/dns/{domain}: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/security/whois/<domain>')
    def get_whois_lookup(domain):
        """API para lookup WHOIS de um domínio"""
        try:
            security_analyzer = SecurityAnalyzer()
            results = security_analyzer.whois_lookup(domain)
            
            return jsonify({
                'success': True,
                'domain': domain,
                'whois_results': results
            })
            
        except Exception as e:
            print(f"[ERRO API] /api/security/whois/{domain}: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/security/virustotal/file/<file_hash>')
    def get_virustotal_file(file_hash):
        """API para verificar arquivo no VirusTotal"""
        try:
            security_analyzer = SecurityAnalyzer()
            results = security_analyzer.check_virustotal_file(file_hash)
            
            return jsonify({
                'success': True,
                'file_hash': file_hash,
                'virustotal_results': results
            })
            
        except Exception as e:
            print(f"[ERRO API] /api/security/virustotal/file/{file_hash}: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/security/virustotal/url', methods=['POST'])
    def check_virustotal_url():
        """API para verificar URL no VirusTotal"""
        try:
            data = request.get_json()
            url = data.get('url', '')
            
            if not url:
                return jsonify({'success': False, 'error': 'URL is required'}), 400
            
            security_analyzer = SecurityAnalyzer()
            results = security_analyzer.check_virustotal_url(url)
            
            return jsonify({
                'success': True,
                'url': url,
                'virustotal_results': results
            })
            
        except Exception as e:
            print(f"[ERRO API] /api/security/virustotal/url: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/security/analyze/pdf', methods=['POST'])
    def analyze_pdf_file():
        """API para análise de arquivo PDF"""
        try:
            if 'file' not in request.files:
                return jsonify({'success': False, 'error': 'No file provided'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'success': False, 'error': 'No file selected'}), 400
            
            # Salvar arquivo temporariamente
            temp_dir = tempfile.mkdtemp()
            temp_path = os.path.join(temp_dir, file.filename)
            file.save(temp_path)
            
            # Calcular hash do arquivo
            with open(temp_path, 'rb') as f:
                file_content = f.read()
                file_hash = hashlib.sha256(file_content).hexdigest()
            
            # Analisar PDF
            security_analyzer = SecurityAnalyzer()
            results = security_analyzer.analyze_pdf(temp_path, file_hash)
            
            # Limpar arquivo temporário
            os.remove(temp_path)
            os.rmdir(temp_dir)
            
            return jsonify({
                'success': True,
                'filename': file.filename,
                'file_hash': file_hash,
                'pdf_analysis': results
            })
            
        except Exception as e:
            print(f"[ERRO API] /api/security/analyze/pdf: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/security/rdns/<ip>')
    def get_reverse_dns(ip):
        """API para lookup rDNS de um IP"""
        try:
            security_analyzer = SecurityAnalyzer()
            results = security_analyzer.reverse_dns_lookup(ip)
            
            return jsonify({
                'success': True,
                'ip': ip,
                'reverse_dns': results
            })
            
        except Exception as e:
            print(f"[ERRO API] /api/security/rdns/{ip}: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/emails/<int:email_id>/preview')
    def get_email_preview(email_id):
        """API para preview seguro do email"""
        try:
            email = db.get_email(email_id)
            if not email:
                return jsonify({'success': False, 'error': 'Email not found'}), 404
            
            email_renderer = EmailRenderer()
            preview = email_renderer.render_email_safely(email)
            
            return jsonify({
                'success': True,
                'email_id': email_id,
                'preview': preview
            })
            
        except Exception as e:
            print(f"[ERRO API] /api/emails/{email_id}/preview: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # ============ RESTANTE DAS ROTAS EXISTENTES ============
    
    @app.route('/api/stats')
    def get_stats():
        """API para estatísticas"""
        try:
            stats = db.get_statistics()
            
            return jsonify({
                'success': True,
                'stats': stats
            })
            
        except Exception as e:
            print(f"[ERRO API] /api/stats: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e),
                'stats': {
                    'total_emails': 0,
                    'unique_domains': 0,
                    'total_attachments': 0,
                    'total_urls': 0,
                    'last_update': datetime.now().isoformat()
                }
            }), 500
    
    @app.route('/api/correlation')
    def get_correlation():
        """API para dados de correlação"""
        try:
            days = min(int(request.args.get('days', 7)), 365)
            correlation = db.get_correlation_data(days)
            
            return jsonify({
                'success': True,
                'correlation': correlation
            })
            
        except Exception as e:
            print(f"[ERRO API] /api/correlation: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e),
                'correlation': {
                    'sender_patterns': [],
                    'hourly_patterns': [],
                    'domain_relations': []
                }
            }), 500
    
    @app.route('/api/domains')
    def get_domains():
        """API para listar domínios"""
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT DISTINCT from_domain 
                    FROM emails 
                    WHERE from_domain != '' AND from_domain IS NOT NULL
                    ORDER BY from_domain
                """)
                domains = [row[0] for row in cursor.fetchall()]
                
            return jsonify({
                'success': True,
                'domains': domains
            })
            
        except Exception as e:
            print(f"[ERRO API] /api/domains: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e),
                'domains': []
            }), 500
    
    # ============ API DE UPLOAD ============
    @app.route('/api/upload/eml', methods=['POST'])
    def upload_eml():
        """API para upload direto de arquivos .eml"""
        try:
            if 'file' not in request.files:
                return jsonify({'success': False, 'error': 'No file provided'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'success': False, 'error': 'No file selected'}), 400
            
            if not file.filename.endswith('.eml'):
                return jsonify({'success': False, 'error': 'File must be .eml format'}), 400
            
            # Verificar se deve pular duplicatas
            skip_duplicate = request.form.get('skip_duplicate', 'true').lower() == 'true'
            
            # Salvar arquivo temporariamente
            temp_path = os.path.join(LOG_FOLDER, f"upload_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
            file.save(temp_path)
            
            # Processar o arquivo
            result = file_processor.process_upload(temp_path, skip_duplicate)
            
            if result.get('success'):
                return jsonify({
                    'success': True,
                    'message': 'Email processed successfully',
                    'email_id': result['email_id'],
                    'file_path': result['file_path']
                })
            elif result.get('duplicate'):
                return jsonify({
                    'success': False,
                    'error': 'Duplicate email',
                    'duplicate': result['duplicate'],
                    'skip': True
                }), 409  # Conflict status code
            else:
                # Remover arquivo temporário em caso de erro
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except:
                        pass
                
                return jsonify({
                    'success': False,
                    'error': result.get('error', 'Failed to process email')
                }), 500
            
        except Exception as e:
            print(f"[ERRO API] /api/upload/eml: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # ============ API DE EXCLUSÃO ============
    @app.route('/api/emails/delete', methods=['POST'])
    def delete_emails():
        """API para excluir emails"""
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({'success': False, 'error': 'No data provided'}), 400
            
            email_ids = data.get('email_ids', [])
            if not email_ids:
                return jsonify({'success': False, 'error': 'No email IDs provided'}), 400
            
            if not isinstance(email_ids, list):
                return jsonify({'success': False, 'error': 'email_ids must be an array'}), 400
            
            # Validar IDs
            try:
                email_ids = [int(id) for id in email_ids]
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid email ID format'}), 400
            
            # Excluir emails
            result = db.delete_emails(email_ids)
            
            if result['success']:
                # Emitir atualização via socketio
                stats = db.get_statistics()
                socketio.emit('stats_update', stats)
                socketio.emit('emails_deleted', {
                    'deleted_ids': email_ids,
                    'count': result['deleted_count']
                })
            
            return jsonify(result)
            
        except Exception as e:
            print(f"[ERRO API] /api/emails/delete: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/emails/delete/all', methods=['POST'])
    def delete_all_emails():
        """API para excluir todos os emails"""
        try:
            # Solicitar confirmação
            data = request.get_json() or {}
            confirm = data.get('confirm', False)
            
            if not confirm:
                return jsonify({
                    'success': False,
                    'error': 'Confirmation required',
                    'message': 'Send {"confirm": true} to delete all emails'
                }), 400
            
            # Excluir todos os emails
            result = db.delete_all_emails()
            
            if result['success']:
                # Emitir atualização via socketio
                stats = db.get_statistics()
                socketio.emit('stats_update', stats)
                socketio.emit('all_emails_deleted', {
                    'deleted_count': result['deleted_count']
                })
            
            return jsonify(result)
            
        except Exception as e:
            print(f"[ERRO API] /api/emails/delete/all: {str(e)}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500