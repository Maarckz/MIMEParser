"""
Ferramentas de segurança e análise avançada para emails
Análise de domínios, URLs, arquivos e renderização segura de emails
"""
import requests
import socket
import json
import time
import re
import hashlib
import urllib.parse
from typing import Dict, List, Optional, Any, Tuple
import subprocess
import tempfile
import os
import traceback
import ipaddress
import warnings
from datetime import datetime

# Suprimir avisos de SSL
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# ============ CONFIGURAÇÃO DE MÓDULOS OPICIONAIS ============
_MODULES = {}

try:
    import whois
    _MODULES['whois'] = whois
    print("[✓] Módulo 'whois' carregado")
except ImportError:
    _MODULES['whois'] = None
    print("[✗] Módulo 'whois' não encontrado. Execute: pip install python-whois")

try:
    import dns.resolver
    _MODULES['dns'] = dns.resolver
    print("[✓] Módulo 'dnspython' carregado")
except ImportError:
    _MODULES['dns'] = None
    print("[✗] Módulo 'dnspython' não encontrado. Execute: pip install dnspython")

try:
    import PyPDF2
    _MODULES['pdf'] = PyPDF2
    print("[✓] Módulo 'PyPDF2' carregado")
except ImportError:
    _MODULES['pdf'] = None
    print("[✗] Módulo 'PyPDF2' não encontrado. Execute: pip install PyPDF2")

try:
    from bs4 import BeautifulSoup
    import bleach
    _MODULES['html'] = {'BeautifulSoup': BeautifulSoup, 'bleach': bleach}
    print("[✓] Módulos HTML (BeautifulSoup4, bleach) carregados")
except ImportError:
    _MODULES['html'] = None
    print("[✗] Módulos HTML não encontrados. Execute: pip install beautifulsoup4 bleach")

try:
    import tldextract
    _MODULES['tld'] = tldextract
    print("[✓] Módulo 'tldextract' carregado")
except ImportError:
    _MODULES['tld'] = None
    print("[✗] Módulo 'tldextract' não encontrado. Execute: pip install tldextract")


# ============ ANALISADOR DE SEGURANÇA ============
class SecurityAnalyzer:
    """Analisador de segurança para URLs, arquivos e domínios"""
    
    # Configuração da API VirusTotal
    VIRUSTOTAL_API_KEY = ""  # Configure sua chave API aqui
    VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3"
    
    # Listas de verificação
    SUSPICIOUS_KEYWORDS = [
        'admin', 'login', 'password', 'verify', 'update', 'security',
        'account', 'bank', 'paypal', 'urgent', 'alert', 'suspended'
    ]
    
    SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.loan', '.download', '.gq']
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Valida se um domínio tem formato válido"""
        if not domain:
            return False
        
        # Regex para validação de domínio
        domain_regex = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        
        if re.match(domain_regex, domain):
            return True
        
        # Aceitar domínios com subdomínios
        if '.' in domain and len(domain) > 3 and len(domain) < 255:
            parts = domain.split('.')
            if len(parts) >= 2:
                return all(part and not part.startswith('-') and not part.endswith('-') 
                          for part in parts[-2:])
        
        return False
    
    @staticmethod
    def extract_domain_from_email(email: str) -> Optional[str]:
        """Extrai domínio de um email de forma segura"""
        if not email or '@' not in email:
            return None
        
        try:
            domain = email.split('@')[-1].strip().lower()
            if SecurityAnalyzer.is_valid_domain(domain):
                return domain
        except Exception:
            pass
        
        return None
    
    @staticmethod
    def dns_lookup(domain: str, timeout: int = 10) -> Dict[str, Any]:
        """Realiza consultas DNS completas para um domínio"""
        if not domain:
            return {'error': 'Domain is required', 'configure': True}
        
        if _MODULES.get('dns') is None:
            return {'domain': domain, 'error': 'DNS module not available', 'configure': True}
        
        try:
            resolver = _MODULES['dns'].Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            
            results = {
                'domain': domain,
                'valid_domain': SecurityAnalyzer.is_valid_domain(domain),
                'a_records': [],
                'aaaa_records': [],
                'mx_records': [],
                'txt_records': [],
                'ns_records': [],
                'soa_record': None,
                'cname_record': None,
                'ptr_records': [],
                'timestamp': datetime.now().isoformat()
            }
            
            # A records (IPv4)
            try:
                answers = resolver.resolve(domain, 'A')
                results['a_records'] = [{'ip': str(r), 'ttl': answers.rrset.ttl if hasattr(answers.rrset, 'ttl') else None} 
                                       for r in answers]
            except (_MODULES['dns'].NoAnswer, _MODULES['dns'].NXDOMAIN, _MODULES['dns'].Timeout):
                results['a_records'] = []
            
            # AAAA records (IPv6)
            try:
                answers = resolver.resolve(domain, 'AAAA')
                results['aaaa_records'] = [{'ip': str(r), 'ttl': answers.rrset.ttl if hasattr(answers.rrset, 'ttl') else None} 
                                          for r in answers]
            except (_MODULES['dns'].NoAnswer, _MODULES['dns'].NXDOMAIN, _MODULES['dns'].Timeout):
                results['aaaa_records'] = []
            
            # MX records
            try:
                answers = resolver.resolve(domain, 'MX')
                results['mx_records'] = [{
                    'priority': r.preference,
                    'server': str(r.exchange),
                    'ttl': answers.rrset.ttl if hasattr(answers.rrset, 'ttl') else None
                } for r in answers]
                results['mx_records'].sort(key=lambda x: x['priority'])
            except (_MODULES['dns'].NoAnswer, _MODULES['dns'].NXDOMAIN, _MODULES['dns'].Timeout):
                results['mx_records'] = []
            
            # TXT records (importante para SPF, DMARC, DKIM)
            try:
                answers = resolver.resolve(domain, 'TXT')
                txt_records = []
                for r in answers:
                    # Decodificar strings de bytes
                    strings = [s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else str(s) 
                              for s in r.strings]
                    txt_records.append({
                        'record': ' '.join(strings),
                        'ttl': answers.rrset.ttl if hasattr(answers.rrset, 'ttl') else None
                    })
                results['txt_records'] = txt_records
                
                # Analisar registros TXT para configurações de segurança
                for record in txt_records:
                    txt = record['record'].lower()
                    if 'v=spf1' in txt:
                        results['has_spf'] = True
                        results['spf_record'] = record['record'][:500]
                    if 'v=dmarc1' in txt:
                        results['has_dmarc'] = True
                        results['dmarc_record'] = record['record'][:500]
                    if 'v=dkim1' in txt or 'k=rsa' in txt:
                        results['has_dkim'] = True
            except (_MODULES['dns'].NoAnswer, _MODULES['dns'].NXDOMAIN, _MODULES['dns'].Timeout):
                results['txt_records'] = []
            
            # NS records
            try:
                answers = resolver.resolve(domain, 'NS')
                results['ns_records'] = [{
                    'server': str(r),
                    'ttl': answers.rrset.ttl if hasattr(answers.rrset, 'ttl') else None
                } for r in answers]
            except (_MODULES['dns'].NoAnswer, _MODULES['dns'].NXDOMAIN, _MODULES['dns'].Timeout):
                results['ns_records'] = []
            
            # SOA record
            try:
                answers = resolver.resolve(domain, 'SOA')
                if answers:
                    soa = answers[0]
                    results['soa_record'] = {
                        'mname': str(soa.mname),
                        'rname': str(soa.rname),
                        'serial': soa.serial,
                        'refresh': soa.refresh,
                        'retry': soa.retry,
                        'expire': soa.expire,
                        'minimum': soa.minimum
                    }
            except (_MODULES['dns'].NoAnswer, _MODULES['dns'].NXDOMAIN, _MODULES['dns'].Timeout):
                pass
            
            # CNAME record
            try:
                answers = resolver.resolve(domain, 'CNAME')
                if answers:
                    results['cname_record'] = str(answers[0].target)
            except (_MODULES['dns'].NoAnswer, _MODULES['dns'].NXDOMAIN, _MODULES['dns'].Timeout):
                pass
            
            # Verificação de reputação
            results['security_indicators'] = SecurityAnalyzer._analyze_dns_security(results)
            
            return results
            
        except Exception as e:
            print(f"[ERRO] DNS lookup para {domain}: {str(e)}")
            traceback.print_exc()
            return {'domain': domain, 'error': str(e), 'configure': False}
    
    @staticmethod
    def _analyze_dns_security(dns_results: Dict) -> Dict:
        """Analisa resultados DNS para indicadores de segurança"""
        indicators = {
            'has_mx': len(dns_results.get('mx_records', [])) > 0,
            'has_spf': dns_results.get('has_spf', False),
            'has_dmarc': dns_results.get('has_dmarc', False),
            'has_dkim': dns_results.get('has_dkim', False),
            'suspicious_tld': False,
            'recently_registered': False,
            'suspicious_keywords': False
        }
        
        domain = dns_results.get('domain', '')
        
        # Verificar TLD suspeito
        if _MODULES.get('tld'):
            try:
                ext = _MODULES['tld'].extract(domain)
                indicators['tld'] = ext.suffix
                indicators['domain_parts'] = {
                    'subdomain': ext.subdomain,
                    'domain': ext.domain,
                    'suffix': ext.suffix
                }
                
                # Verificar TLDs suspeitos
                if ext.suffix in SecurityAnalyzer.SUSPICIOUS_TLDS:
                    indicators['suspicious_tld'] = True
            except:
                pass
        
        # Verificar palavras-chave suspeitas no domínio
        domain_lower = domain.lower()
        for keyword in SecurityAnalyzer.SUSPICIOUS_KEYWORDS:
            if keyword in domain_lower:
                indicators['suspicious_keywords'] = True
                break
        
        # Calcular pontuação de risco
        risk_score = 0
        if not indicators['has_mx']:
            risk_score += 2
        if not indicators['has_spf']:
            risk_score += 1
        if not indicators['has_dmarc']:
            risk_score += 1
        if indicators['suspicious_tld']:
            risk_score += 2
        if indicators['suspicious_keywords']:
            risk_score += 1
        
        indicators['risk_score'] = min(risk_score, 10)
        indicators['risk_level'] = 'low' if risk_score <= 2 else 'medium' if risk_score <= 5 else 'high'
        
        return indicators
    
    @staticmethod
    def whois_lookup(domain: str) -> Dict[str, Any]:
        """Consulta informações WHOIS de um domínio"""
        if not domain:
            return {'error': 'Domain is required', 'configure': True}
        
        if _MODULES.get('whois') is None:
            return {'domain': domain, 'error': 'WHOIS module not available', 'configure': True}
        
        try:
            w = _MODULES['whois'].whois(domain)
            
            results = {
                'domain': domain,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'org': w.org,
                'country': w.country,
                'name': w.name,
                'address': w.address,
                'city': w.city,
                'state': w.state,
                'zipcode': w.zipcode,
                'dnssec': w.dnssec,
                'timestamp': datetime.now().isoformat()
            }
            
            # Limpar e padronizar resultados
            for key in ['name_servers', 'status', 'emails']:
                if results[key] and isinstance(results[key], list):
                    results[key] = [str(item) for item in results[key]]
                elif results[key]:
                    results[key] = str(results[key])
            
            # Analisar idade do domínio
            if results['creation_date']:
                try:
                    if isinstance(results['creation_date'], list):
                        creation_str = results['creation_date'][0]
                    else:
                        creation_str = results['creation_date']
                    
                    creation_date = datetime.fromisoformat(creation_str.replace('Z', '+00:00'))
                    age_days = (datetime.now() - creation_date).days
                    results['domain_age_days'] = age_days
                    results['is_new_domain'] = age_days < 30  # Domínio com menos de 30 dias
                except:
                    results['domain_age_days'] = None
                    results['is_new_domain'] = None
            
            return results
            
        except Exception as e:
            print(f"[ERRO] WHOIS lookup para {domain}: {str(e)}")
            return {'domain': domain, 'error': str(e), 'configure': False}
    
    @staticmethod
    def check_virustotal_file(file_hash: str) -> Dict[str, Any]:
        """Consulta um arquivo no VirusTotal pelo hash"""
        if not SecurityAnalyzer.VIRUSTOTAL_API_KEY:
            return {'error': 'VirusTotal API key not configured', 'configure': True}
        
        if not file_hash or len(file_hash) not in [32, 40, 64]:  # MD5, SHA-1, SHA-256
            return {'error': 'Invalid file hash format', 'configure': False}
        
        try:
            headers = {
                'x-apikey': SecurityAnalyzer.VIRUSTOTAL_API_KEY,
                'Accept': 'application/json'
            }
            
            # Primeiro, obter análise do arquivo
            url = f"{SecurityAnalyzer.VIRUSTOTAL_URL}/files/{file_hash}"
            response = requests.get(url, headers=headers, timeout=30, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                # Calcular detecções
                last_analysis = attributes.get('last_analysis_stats', {})
                total_engines = sum(last_analysis.values())
                malicious_count = last_analysis.get('malicious', 0)
                suspicious_count = last_analysis.get('suspicious', 0)
                detection_rate = (malicious_count + suspicious_count) / total_engines if total_engines > 0 else 0
                
                results = {
                    'file_hash': file_hash,
                    'detection_rate': round(detection_rate * 100, 2),
                    'malicious': malicious_count,
                    'suspicious': suspicious_count,
                    'undetected': last_analysis.get('undetected', 0),
                    'harmless': last_analysis.get('harmless', 0),
                    'total_engines': total_engines,
                    'meaningful_name': attributes.get('meaningful_name', ''),
                    'size': attributes.get('size', 0),
                    'type_tag': attributes.get('type_tag', ''),
                    'reputation': attributes.get('reputation', 0),
                    'magic': attributes.get('magic', ''),
                    'sha256': attributes.get('sha256', ''),
                    'sha1': attributes.get('sha1', ''),
                    'md5': attributes.get('md5', ''),
                    'first_submission': attributes.get('first_submission_date'),
                    'last_analysis': attributes.get('last_analysis_date'),
                    'times_submitted': attributes.get('times_submitted', 0),
                    'popular_threat_classification': attributes.get('popular_threat_classification', {}),
                    'tags': attributes.get('tags', []),
                    'is_malicious': detection_rate > 0.1,  # Mais de 10% de detecção
                    'timestamp': datetime.now().isoformat()
                }
                
                return results
            elif response.status_code == 404:
                return {'file_hash': file_hash, 'status': 'not_found', 'timestamp': datetime.now().isoformat()}
            else:
                return {
                    'file_hash': file_hash, 
                    'error': f'API error: {response.status_code}',
                    'status_code': response.status_code,
                    'timestamp': datetime.now().isoformat()
                }
                
        except requests.exceptions.Timeout:
            return {'file_hash': file_hash, 'error': 'API timeout', 'configure': False}
        except Exception as e:
            print(f"[ERRO] VirusTotal lookup para {file_hash}: {str(e)}")
            return {'file_hash': file_hash, 'error': str(e), 'configure': False}
    
    @staticmethod
    def check_virustotal_url(url: str) -> Dict[str, Any]:
        """Consulta uma URL no VirusTotal"""
        if not SecurityAnalyzer.VIRUSTOTAL_API_KEY:
            return {'error': 'VirusTotal API key not configured', 'configure': True}
        
        if not url or not url.startswith(('http://', 'https://')):
            return {'error': 'Invalid URL format', 'configure': False}
        
        try:
            headers = {
                'x-apikey': SecurityAnalyzer.VIRUSTOTAL_API_KEY,
                'Accept': 'application/json'
            }
            
            # Primeiro, submeter URL para análise
            submit_url = f"{SecurityAnalyzer.VIRUSTOTAL_URL}/urls"
            
            # Extrair domínio para análise
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            
            response = requests.post(
                submit_url,
                headers=headers,
                data={'url': url},
                timeout=30,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get('data', {}).get('id', '')
                
                # Aguardar um momento e obter resultado
                time.sleep(2)
                
                analysis_url = f"{SecurityAnalyzer.VIRUSTOTAL_URL}/analyses/{analysis_id}"
                analysis_response = requests.get(analysis_url, headers=headers, timeout=30, verify=False)
                
                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json()
                    attributes = analysis_data.get('data', {}).get('attributes', {})
                    
                    stats = attributes.get('stats', {})
                    total = sum(stats.values())
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    detection_rate = (malicious + suspicious) / total if total > 0 else 0
                    
                    results = {
                        'url': url,
                        'domain': domain,
                        'detection_rate': round(detection_rate * 100, 2),
                        'stats': stats,
                        'status': attributes.get('status', ''),
                        'analysis_date': attributes.get('date', None),
                        'is_malicious': detection_rate > 0.1,
                        'redirects_to': None,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Verificar redirecionamentos
                    if 'redirects' in analysis_data.get('data', {}).get('attributes', {}):
                        redirects = analysis_data['data']['attributes']['redirects']
                        if redirects:
                            results['redirects_to'] = redirects[-1].get('url') if redirects else None
                    
                    return results
                else:
                    return {
                        'url': url, 
                        'error': f'Analysis error: {analysis_response.status_code}',
                        'timestamp': datetime.now().isoformat()
                    }
            else:
                return {
                    'url': url, 
                    'error': f'Submission error: {response.status_code}',
                    'timestamp': datetime.now().isoformat()
                }
                
        except requests.exceptions.Timeout:
            return {'url': url, 'error': 'API timeout', 'configure': False}
        except Exception as e:
            print(f"[ERRO] VirusTotal URL check para {url}: {str(e)}")
            return {'url': url, 'error': str(e), 'configure': False}
    
    @staticmethod
    def analyze_pdf(file_path: str, file_hash: str) -> Dict[str, Any]:
        """Análise avançada de arquivo PDF"""
        if _MODULES.get('pdf') is None:
            return {
                'file_path': file_path,
                'file_hash': file_hash,
                'error': 'PDF analysis module not available',
                'configure': True
            }
        
        try:
            results = {
                'file_path': file_path,
                'file_hash': file_hash,
                'has_javascript': False,
                'has_actions': False,
                'has_embedded_files': False,
                'has_forms': False,
                'is_encrypted': False,
                'num_pages': 0,
                'metadata': {},
                'text_preview': '',
                'pdf_version': '',
                'creation_date': None,
                'modification_date': None,
                'title': '',
                'author': '',
                'producer': '',
                'creator': '',
                'keywords': '',
                'subject': '',
                'suspicious_elements': [],
                'timestamp': datetime.now().isoformat()
            }
            
            with open(file_path, 'rb') as f:
                pdf_reader = _MODULES['pdf'].PdfReader(f)
                
                results['num_pages'] = len(pdf_reader.pages)
                results['is_encrypted'] = pdf_reader.is_encrypted
                results['pdf_version'] = pdf_reader.pdf_header if hasattr(pdf_reader, 'pdf_header') else 'Unknown'
                
                # Extrair metadados
                if pdf_reader.metadata:
                    metadata = dict(pdf_reader.metadata)
                    results['metadata'] = metadata
                    
                    # Extrair campos específicos
                    for key, value in metadata.items():
                        key_lower = key.lower()
                        if 'title' in key_lower:
                            results['title'] = str(value)[:200]
                        elif 'author' in key_lower:
                            results['author'] = str(value)[:200]
                        elif 'producer' in key_lower:
                            results['producer'] = str(value)[:200]
                        elif 'creator' in key_lower:
                            results['creator'] = str(value)[:200]
                        elif 'keywords' in key_lower:
                            results['keywords'] = str(value)[:500]
                        elif 'subject' in key_lower:
                            results['subject'] = str(value)[:500]
                        elif 'creationdate' in key_lower:
                            results['creation_date'] = str(value)[:100]
                        elif 'moddate' in key_lower:
                            results['modification_date'] = str(value)[:100]
                
                # Analisar páginas
                for i, page in enumerate(pdf_reader.pages[:10]):  # Limitar a 10 páginas para performance
                    try:
                        # Extrair texto
                        text = page.extract_text()
                        if text and not results['text_preview']:
                            results['text_preview'] = text[:1000] + ('...' if len(text) > 1000 else '')
                        
                        # Verificar por JavaScript (/JS ou /JavaScript)
                        page_content = str(page)
                        if '/JS' in page_content or '/JavaScript' in page_content:
                            results['has_javascript'] = True
                            results['suspicious_elements'].append('javascript')
                        
                        # Verificar por ações (/AA)
                        if '/AA' in page_content:
                            results['has_actions'] = True
                            results['suspicious_elements'].append('actions')
                        
                        # Verificar por formulários (/AcroForm)
                        if '/AcroForm' in page_content:
                            results['has_forms'] = True
                        
                        # Verificar por arquivos embutidos
                        if '/EmbeddedFiles' in page_content or '/EmbeddedFile' in page_content:
                            results['has_embedded_files'] = True
                            results['suspicious_elements'].append('embedded_files')
                            
                    except Exception as e:
                        print(f"[AVISO] Erro ao analisar página {i+1}: {str(e)}")
                
                # Verificar se tem anexos
                if hasattr(pdf_reader, 'attachments'):
                    try:
                        if pdf_reader.attachments:
                            results['has_embedded_files'] = True
                            results['attachment_count'] = len(pdf_reader.attachments)
                    except:
                        pass
            
            # Analisar risco
            risk_score = 0
            if results['has_javascript']:
                risk_score += 3
            if results['has_actions']:
                risk_score += 2
            if results['has_forms']:
                risk_score += 2
            if results['has_embedded_files']:
                risk_score += 3
            if results['is_encrypted']:
                risk_score += 1
            
            results['risk_score'] = min(risk_score, 10)
            results['risk_level'] = 'low' if risk_score <= 2 else 'medium' if risk_score <= 5 else 'high'
            
            return results
            
        except Exception as e:
            print(f"[ERRO] Análise PDF para {file_path}: {str(e)}")
            return {
                'file_path': file_path,
                'file_hash': file_hash,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    @staticmethod
    def reverse_dns_lookup(ip: str) -> Dict[str, Any]:
        """Realiza consulta rDNS (PTR) para um IP"""
        if not ip:
            return {'error': 'IP is required', 'configure': False}
        
        try:
            # Validar formato do IP
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return {'ip': ip, 'error': 'Invalid IP address format', 'configure': False}
            
            results = {
                'ip': ip,
                'hostname': None,
                'aliases': [],
                'timestamp': datetime.now().isoformat()
            }
            
            try:
                # Consulta rDNS
                hostname, aliaslist, _ = socket.gethostbyaddr(ip)
                results['hostname'] = hostname
                results['aliases'] = aliaslist if aliaslist else []
                
                # Análise do hostname
                if hostname:
                    # Verificar se é um domínio válido
                    if SecurityAnalyzer.is_valid_domain(hostname):
                        results['valid_domain'] = True
                        
                        # Extrair TLD se possível
                        if _MODULES.get('tld'):
                            try:
                                ext = _MODULES['tld'].extract(hostname)
                                results['domain_parts'] = {
                                    'subdomain': ext.subdomain,
                                    'domain': ext.domain,
                                    'tld': ext.suffix
                                }
                            except:
                                pass
                    else:
                        results['valid_domain'] = False
                    
                    # Verificar se é um PTR padrão (ex: 1.2.3.4.in-addr.arpa)
                    if hostname.endswith('.in-addr.arpa') or hostname.endswith('.ip6.arpa'):
                        results['is_reverse_ptr'] = True
                    else:
                        results['is_reverse_ptr'] = False
                        
            except socket.herror:
                results['hostname'] = None
                results['error'] = 'No PTR record found'
            except socket.gaierror:
                results['hostname'] = None
                results['error'] = 'Address resolution error'
            
            return results
            
        except Exception as e:
            print(f"[ERRO] rDNS lookup para {ip}: {str(e)}")
            return {'ip': ip, 'error': str(e), 'configure': False}
    
    @staticmethod
    def analyze_binary_file(file_path: str, file_hash: str) -> Dict[str, Any]:
        """Análise de arquivo binário usando strings e file command"""
        try:
            results = {
                'file_path': file_path,
                'file_hash': file_hash,
                'file_type': 'unknown',
                'magic_bytes': '',
                'strings_found': [],
                'interesting_strings': [],
                'entropy': 0.0,
                'suspicious_patterns': [],
                'timestamp': datetime.now().isoformat()
            }
            
            # Verificar se arquivo existe
            if not os.path.exists(file_path):
                return {'error': 'File not found', 'file_path': file_path, 'configure': False}
            
            # Determinar tipo de arquivo usando file command
            try:
                file_type_result = subprocess.run(
                    ['file', '-b', '--mime-type', file_path],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=True
                )
                results['file_type'] = file_type_result.stdout.strip()
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                pass
            
            # Extrair magic bytes (primeiros bytes)
            try:
                with open(file_path, 'rb') as f:
                    magic = f.read(64)
                    results['magic_bytes'] = magic.hex()[:128]  # Limitar a 128 chars
            except:
                pass
            
            # Extrair strings
            try:
                strings_result = subprocess.run(
                    ['strings', '-n', '6', file_path],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=True
                )
                all_strings = strings_result.stdout.split('\n')
                results['strings_found'] = len(all_strings)
                
                # Filtrar strings interessantes
                interesting = []
                url_pattern = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+\.[a-zA-Z]{2,}')
                email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
                ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
                
                suspicious_keywords = [
                    r'eval\s*\(', r'exec\s*\(', r'system\s*\(', r'shell_exec',
                    r'cmd\.exe', r'powershell', r'wscript\.shell', r'regsvr32',
                    r'javascript:', r'vbscript:', r'<script', r'</script>'
                ]
                
                for string in all_strings:
                    string = string.strip()
                    if len(string) < 6:
                        continue
                    
                    entry = {'string': string, 'type': 'text', 'length': len(string)}
                    
                    # URLs
                    url_match = url_pattern.search(string)
                    if url_match:
                        entry['type'] = 'url'
                        entry['value'] = url_match.group()
                        interesting.append(entry)
                        continue
                    
                    # Emails
                    email_match = email_pattern.search(string)
                    if email_match:
                        entry['type'] = 'email'
                        entry['value'] = email_match.group()
                        interesting.append(entry)
                        continue
                    
                    # IPs
                    ip_match = ip_pattern.search(string)
                    if ip_match and ip_match.group().count('.') == 3:
                        try:
                            ipaddress.ip_address(ip_match.group())
                            entry['type'] = 'ip'
                            entry['value'] = ip_match.group()
                            interesting.append(entry)
                            continue
                        except:
                            pass
                    
                    # Comandos suspeitos
                    for pattern in suspicious_keywords:
                        if re.search(pattern, string, re.IGNORECASE):
                            entry['type'] = 'suspicious'
                            entry['value'] = string
                            interesting.append(entry)
                            results['suspicious_patterns'].append(pattern)
                            break
                    
                    # Strings longas (> 100 chars) podem ser interessantes
                    if len(string) > 100 and len(interesting) < 50:
                        entry['type'] = 'long_string'
                        entry['value'] = string[:200] + '...' if len(string) > 200 else string
                        interesting.append(entry)
                
                # Limitar a 100 strings interessantes
                results['interesting_strings'] = interesting[:100]
                
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                pass
            
            return results
            
        except Exception as e:
            print(f"[ERRO] Análise binária para {file_path}: {str(e)}")
            return {
                'file_path': file_path,
                'file_hash': file_hash,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    @staticmethod
    def analyze_email_headers(headers: Dict) -> Dict[str, Any]:
        """Análise de segurança dos cabeçalhos de email"""
        try:
            analysis = {
                'received_chain': [],
                'spoofing_indicators': [],
                'security_headers': {},
                'missing_security': [],
                'anomalies': [],
                'score': 0,
                'timestamp': datetime.now().isoformat()
            }
            
            # Analisar Received headers
            if 'received' in headers:
                received = headers['received']
                if isinstance(received, list):
                    analysis['received_chain'] = received
                    
                    # Verificar consistência na cadeia
                    if len(received) > 1:
                        first_ip = None
                        last_ip = None
                        
                        # Extrair IPs do primeiro e último Received
                        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                        
                        if received[0]:
                            matches = re.findall(ip_pattern, received[0])
                            if matches:
                                first_ip = matches[-1]
                        
                        if received[-1]:
                            matches = re.findall(ip_pattern, received[-1])
                            if matches:
                                last_ip = matches[-1]
                        
                        if first_ip and last_ip and first_ip != last_ip:
                            analysis['anomalies'].append('IP mismatch in received chain')
                            analysis['score'] += 2
            
            # Verificar headers de segurança
            security_headers = ['Authentication-Results', 'DKIM-Signature', 
                              'ARC-Authentication-Results', 'X-Mailer', 'User-Agent']
            
            for header in security_headers:
                if header.lower() in [h.lower() for h in headers]:
                    key = next((h for h in headers if h.lower() == header.lower()), header)
                    analysis['security_headers'][header] = headers[key]
                else:
                    analysis['missing_security'].append(header)
                    if header in ['Authentication-Results', 'DKIM-Signature']:
                        analysis['score'] += 1
            
            # Verificar Return-Path vs From
            if 'return-path' in headers and 'from' in headers:
                return_path = headers['return-path'].lower()
                from_addr = headers['from'].lower()
                
                # Extrair domínios
                def extract_domain(addr):
                    if '<' in addr and '>' in addr:
                        match = re.search(r'<([^>]+)>', addr)
                        if match:
                            addr = match.group(1)
                    if '@' in addr:
                        return addr.split('@')[-1].strip('>')
                    return None
                
                rp_domain = extract_domain(return_path)
                from_domain = extract_domain(from_addr)
                
                if rp_domain and from_domain and rp_domain != from_domain:
                    analysis['spoofing_indicators'].append('Return-Path domain differs from From domain')
                    analysis['score'] += 3
            
            # Verificar Message-ID consistente
            if 'message-id' in headers:
                msg_id = headers['message-id']
                if not (msg_id.startswith('<') and msg_id.endswith('>')):
                    analysis['anomalies'].append('Message-ID malformed')
                    analysis['score'] += 1
            
            # Calcular pontuação final
            max_score = 10
            analysis['score'] = min(analysis['score'], max_score)
            analysis['risk_level'] = 'low' if analysis['score'] <= 3 else 'medium' if analysis['score'] <= 7 else 'high'
            
            return analysis
            
        except Exception as e:
            print(f"[ERRO] Análise de cabeçalhos: {str(e)}")
            return {'error': str(e), 'configure': False}


# ============ RENDERIZADOR DE EMAILS SEGURO ============
class EmailRenderer:
    """Renderizador seguro de emails com sanitização completa"""
    
    ALLOWED_TAGS = [
        'a', 'abbr', 'acronym', 'address', 'b', 'br', 'blockquote', 'cite', 'code',
        'div', 'dl', 'dt', 'dd', 'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr',
        'i', 'img', 'li', 'ol', 'p', 'pre', 'q', 's', 'small', 'span', 'strike',
        'strong', 'sub', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th', 'thead',
        'tr', 'tt', 'u', 'ul'
    ]
    
    ALLOWED_ATTRIBUTES = {
        'a': ['href', 'title', 'target', 'rel'],
        'img': ['src', 'alt', 'title', 'width', 'height'],
        '*': ['style', 'class', 'id']
    }
    
    ALLOWED_STYLES = [
        'color', 'background-color', 'font-size', 'font-family', 
        'font-weight', 'text-align', 'text-decoration'
    ]
    
    @staticmethod
    def render_email_safely(email_data: Dict) -> Dict[str, Any]:
        """Renderiza um email de forma segura para visualização"""
        try:
            # Extrair dados do email
            metadata = email_data.get('metadata', {})
            content = email_data.get('analysis', {}).get('content_analysis', {})
            raw_data = email_data.get('raw_data', {})
            
            result = {
                'headers': {},
                'body_preview': {},
                'attachments_info': [],
                'is_safe': True,
                'warnings': [],
                'security_indicators': [],
                'timestamp': datetime.now().isoformat()
            }
            
            # Extrair cabeçalhos importantes
            important_headers = [
                'From', 'To', 'Subject', 'Date', 'Message-ID', 'Return-Path',
                'Sender', 'Reply-To', 'In-Reply-To', 'CC', 'BCC', 'X-Mailer',
                'Content-Type', 'MIME-Version', 'Received', 'X-Originating-IP',
                'X-Priority', 'Importance', 'List-Unsubscribe'
            ]
            
            # Obter cabeçalhos de múltiplas fontes
            all_headers = {}
            
            # 1. Do metadata
            if isinstance(metadata, dict):
                all_headers.update(metadata)
            
            # 2. Do raw_data
            if isinstance(raw_data, dict):
                raw_metadata = raw_data.get('metadata', {})
                if isinstance(raw_metadata, dict):
                    all_headers.update(raw_metadata)
            
            # Processar cada cabeçalho importante
            for header in important_headers:
                header_lower = header.lower()
                value = None
                
                # Buscar pelo nome exato primeiro
                if header in all_headers:
                    value = all_headers[header]
                # Buscar por lowercase
                elif header_lower in all_headers:
                    value = all_headers[header_lower]
                # Buscar por qualquer variação de case
                else:
                    for key in all_headers.keys():
                        if isinstance(key, str) and key.lower() == header_lower:
                            value = all_headers[key]
                            break
                
                if value:
                    # Limitar comprimento e sanitizar
                    safe_value = EmailRenderer._sanitize_header_value(str(value))
                    result['headers'][header] = safe_value
            
            # Análise de segurança dos cabeçalhos
            result['header_analysis'] = SecurityAnalyzer.analyze_email_headers(result['headers'])
            
            # Processar corpo do email de forma segura
            text_parts = content.get('text_parts', [])
            html_parts = content.get('html_parts', [])
            
            # Texto plano
            if text_parts and isinstance(text_parts, list):
                for i, part in enumerate(text_parts[:3]):  # Limitar a 3 partes de texto
                    if isinstance(part, dict):
                        text_content = part.get('text_preview') or part.get('content') or part.get('text', '')
                        if text_content:
                            safe_text = EmailRenderer._sanitize_text(text_content)
                            result['body_preview'][f'text_part_{i+1}'] = {
                                'type': 'text',
                                'content': safe_text[:2000],  # Limitar
                                'charset': part.get('charset', 'utf-8'),
                                'size': len(text_content)
                            }
                            break  # Usar apenas a primeira parte
            
            # HTML
            if html_parts and isinstance(html_parts, list):
                for i, part in enumerate(html_parts[:2]):  # Limitar a 2 partes HTML
                    if isinstance(part, dict):
                        html_content = part.get('text_preview') or part.get('content') or part.get('html', '')
                        if html_content:
                            safe_html = EmailRenderer._sanitize_html(html_content)
                            result['body_preview'][f'html_part_{i+1}'] = {
                                'type': 'html',
                                'content': safe_html[:5000],  # Limitar
                                'charset': part.get('charset', 'utf-8'),
                                'size': len(html_content),
                                'sanitized': True
                            }
                            result['warnings'].append('HTML content sanitized for security')
                            break  # Usar apenas a primeira parte
            
            # Informações de anexos
            attachments = content.get('attachments', [])
            if isinstance(attachments, list):
                for i, att in enumerate(attachments[:10]):  # Limitar a 10 anexos
                    if isinstance(att, dict):
                        att_info = {
                            'index': i,
                            'filename': EmailRenderer._sanitize_filename(att.get('filename', 'Unknown')),
                            'size': att.get('size_bytes', 0),
                            'type': att.get('content_type', 'Unknown'),
                            'md5': att.get('md5', ''),
                            'sha256': att.get('sha256', ''),
                            'is_suspicious': False
                        }
                        
                        # Verificar extensões suspeitas
                        filename = att_info['filename'].lower()
                        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.ps1', 
                                               '.vbs', '.js', '.jar', '.dll', '.hta']
                        
                        if any(filename.endswith(ext) for ext in suspicious_extensions):
                            att_info['is_suspicious'] = True
                            result['security_indicators'].append(f'Suspicious attachment: {filename}')
                        
                        result['attachments_info'].append(att_info)
            
            # URLs no corpo
            urls = content.get('urls', [])
            if isinstance(urls, list):
                result['urls_found'] = []
                for i, url in enumerate(urls[:20]):  # Limitar a 20 URLs
                    if isinstance(url, dict):
                        url_info = {
                            'url': url.get('url', ''),
                            'text': url.get('text', '')[:100],
                            'is_suspicious': False
                        }
                        
                        # Verificar URLs suspeitas
                        url_lower = url_info['url'].lower()
                        if any(keyword in url_lower for keyword in ['login', 'password', 'verify', 'account']):
                            url_info['is_suspicious'] = True
                            result['security_indicators'].append(f'Suspicious URL: {url_info["url"][:50]}...')
                        
                        result['urls_found'].append(url_info)
            
            return result
            
        except Exception as e:
            print(f"[ERRO] Renderização segura de email: {str(e)}")
            traceback.print_exc()
            return {
                'headers': {},
                'body_preview': {},
                'attachments_info': [],
                'is_safe': False,
                'warnings': ['Error rendering email safely'],
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    @staticmethod
    def _sanitize_header_value(value: str, max_length: int = 500) -> str:
        """Sanitiza valores de cabeçalho"""
        if not value:
            return ""
        
        # Remover caracteres de controle
        value = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value)
        
        # Remover múltiplos espaços
        value = re.sub(r'\s+', ' ', value)
        
        # Limitar comprimento
        if len(value) > max_length:
            value = value[:max_length] + '...'
        
        return value.strip()
    
    @staticmethod
    def _sanitize_filename(filename: str) -> str:
        """Sanitiza nomes de arquivo"""
        if not filename:
            return "Unknown"
        
        # Remover caracteres perigosos
        dangerous = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
        for char in dangerous:
            filename = filename.replace(char, '_')
        
        # Limitar comprimento
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:250 - len(ext)] + ext
        
        return filename
    
    @staticmethod
    def _sanitize_text(text: str, max_length: int = 10000) -> str:
        """Sanitiza texto plano"""
        if not text:
            return ""
        
        # Remover caracteres de controle (exceto quebra de linha e tab)
        text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
        
        # Codificar caracteres especiais
        text = text.encode('ascii', 'ignore').decode('ascii')
        
        # Limitar comprimento
        if len(text) > max_length:
            text = text[:max_length] + '... [TRUNCATED]'
        
        return text
    
    @staticmethod
    def _sanitize_html(html: str, max_length: int = 20000) -> str:
        """Sanitiza HTML removendo tags e atributos perigosos"""
        if not html:
            return ""
        
        try:
            # Se os módulos de sanitização não estiverem disponíveis, use fallback básico
            if _MODULES.get('html') is None:
                # Fallback seguro: remover todas as tags HTML
                html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
                html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
                html = re.sub(r'on\w+\s*=\s*["\'][^"\']*["\']', '', html, flags=re.IGNORECASE)
                html = re.sub(r'javascript:', '', html, flags=re.IGNORECASE)
                html = re.sub(r'vbscript:', '', html, flags=re.IGNORECASE)
                html = re.sub(r'data:', '', html, flags=re.IGNORECASE)
                html = re.sub(r'<[^>]+>', '', html)
                return html[:5000]
            
            BeautifulSoup = _MODULES['html']['BeautifulSoup']
            bleach = _MODULES['html']['bleach']
            
            # Parse HTML
            soup = BeautifulSoup(html, 'html.parser')
            
            # Remover scripts, styles e meta tags perigosas
            for tag in soup(['script', 'style', 'meta', 'link', 'iframe', 'frame', 'frameset', 'object', 'embed']):
                tag.decompose()
            
            # Remover atributos de eventos
            for tag in soup.find_all(True):
                attrs = dict(tag.attrs)
                for attr in list(attrs.keys()):
                    if attr.lower().startswith('on'):
                        del tag.attrs[attr]
                    elif attr.lower() in ['href', 'src']:
                        value = attrs[attr]
                        if isinstance(value, str):
                            if value.lower().startswith(('javascript:', 'vbscript:', 'data:')):
                                del tag.attrs[attr]
            
            html = str(soup)
            
            # Usar bleach para sanitização final
            clean_html = bleach.clean(
                html,
                tags=EmailRenderer.ALLOWED_TAGS,
                attributes=EmailRenderer.ALLOWED_ATTRIBUTES,
                styles=EmailRenderer.ALLOWED_STYLES,
                strip=True,
                strip_comments=True
            )
            
            # Limitar comprimento
            if len(clean_html) > max_length:
                clean_html = clean_html[:max_length] + '... [TRUNCATED]'
            
            return clean_html
            
        except Exception as e:
            print(f"[ERRO] Sanitização HTML: {str(e)}")
            # Fallback extremo: converter para texto
            return re.sub(r'<[^>]+>', '', html)[:5000]
    
    @staticmethod
    def extract_viewable_content(email_data: Dict) -> Dict[str, Any]:
        """Extrai conteúdo visualizável do email de forma segura"""
        try:
            rendered = EmailRenderer.render_email_safely(email_data)
            
            result = {
                'subject': rendered['headers'].get('Subject', 'No Subject'),
                'from': rendered['headers'].get('From', 'Unknown'),
                'to': rendered['headers'].get('To', 'Unknown'),
                'date': rendered['headers'].get('Date', 'Unknown'),
                'message_id': rendered['headers'].get('Message-ID', ''),
                'body': '',
                'body_type': 'text',
                'attachments_count': len(rendered.get('attachments_info', [])),
                'urls_count': len(rendered.get('urls_found', [])),
                'is_safe': rendered.get('is_safe', False),
                'warnings': rendered.get('warnings', [])
            }
            
            # Escolher o melhor conteúdo para exibição
            body_preview = rendered.get('body_preview', {})
            
            # Preferir texto sobre HTML para segurança
            for key, content in body_preview.items():
                if content.get('type') == 'text' and content.get('content'):
                    result['body'] = content['content']
                    result['body_type'] = 'text'
                    break
                elif content.get('type') == 'html' and content.get('content'):
                    result['body'] = content['content']
                    result['body_type'] = 'html'
                    # Não break para dar preferência ao texto
            
            # Se nenhum conteúdo encontrado
            if not result['body']:
                result['body'] = '[No viewable content found]'
                result['body_type'] = 'text'
            
            return result
            
        except Exception as e:
            print(f"[ERRO] Extração de conteúdo: {str(e)}")
            return {
                'subject': 'Error',
                'from': 'Unknown',
                'to': 'Unknown',
                'date': 'Unknown',
                'message_id': '',
                'body': f'Error extracting content: {str(e)}',
                'body_type': 'text',
                'attachments_count': 0,
                'urls_count': 0,
                'is_safe': False,
                'warnings': ['Error extracting viewable content']
            }


# ============ FUNÇÕES DE UTILIDADE ============
def test_security_modules() -> Dict[str, bool]:
    """Testa todos os módulos de segurança"""
    results = {}
    
    modules_to_test = [
        ('DNS', _MODULES.get('dns')),
        ('WHOIS', _MODULES.get('whois')),
        ('PDF', _MODULES.get('pdf')),
        ('HTML', _MODULES.get('html')),
        ('TLD', _MODULES.get('tld'))
    ]
    
    for name, module in modules_to_test:
        results[name] = module is not None
    
    # Testar conexão básica
    try:
        socket.create_connection(('8.8.8.8', 53), timeout=2)
        results['Network'] = True
    except:
        results['Network'] = False
    
    # Verificar VirusTotal API
    results['VirusTotal'] = bool(SecurityAnalyzer.VIRUSTOTAL_API_KEY)
    
    return results


def get_module_status() -> Dict[str, str]:
    """Retorna status detalhado dos módulos"""
    status = {}
    
    if _MODULES.get('dns'):
        status['DNS'] = f'Available (dnspython {_MODULES["dns"].__version__})'
    else:
        status['DNS'] = 'Not available - pip install dnspython'
    
    if _MODULES.get('whois'):
        status['WHOIS'] = f'Available (whois {_MODULES["whois"].__version__})'
    else:
        status['WHOIS'] = 'Not available - pip install python-whois'
    
    if _MODULES.get('pdf'):
        status['PDF'] = f'Available (PyPDF2 {_MODULES["pdf"].__version__})'
    else:
        status['PDF'] = 'Not available - pip install PyPDF2'
    
    if _MODULES.get('html'):
        status['HTML'] = 'Available (BeautifulSoup4, bleach)'
    else:
        status['HTML'] = 'Not available - pip install beautifulsoup4 bleach'
    
    if _MODULES.get('tld'):
        status['TLD'] = f'Available (tldextract {_MODULES["tld"].__version__})'
    else:
        status['TLD'] = 'Not available - pip install tldextract'
    
    status['VirusTotal'] = 'Configured' if SecurityAnalyzer.VIRUSTOTAL_API_KEY else 'Not configured'
    
    return status


# Inicialização
if __name__ == "__main__":
    print("=" * 60)
    print("Security Tools Module - Status Check")
    print("=" * 60)
    
    status = get_module_status()
    for module, state in status.items():
        print(f"{module:15} : {state}")
    
    print("=" * 60)
    print("Nota: Configure VIRUSTOTAL_API_KEY no código para usar VirusTotal")
    print("=" * 60)