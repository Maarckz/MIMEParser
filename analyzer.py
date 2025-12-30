import re
import hashlib
import email
import ipaddress
import base64
import quopri
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.header import decode_header
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse
import os
import traceback
import socket


# ============ MIME FORENSIC EXTRACTOR ============
class MIMEForensicExtractor:
    def __init__(self, email_content: bytes):
        """Inicializa o extrator forense MIME."""
        self.email_content = email_content
        self.message = BytesParser(policy=policy.default).parsebytes(email_content)
        
        # Resultados focados em dados técnicos brutos
        self.results = {
            'metadata': {
                'from': '',
                'to': '',
                'subject': '',
                'date': '',
                'message_id': '',
                'return_path': '',
                'size_bytes': 0,
                'display_name': '',
                'sender': '',
                'cc': '',
                'bcc': '',
                'in_reply_to': '',
                'reply_to': '',
                'originating_ip': None,
                'x_mailer': '',
                'content_type': '',
                'mime_version': ''
            },
            'authentication': {
                'spf': {'status': 'none', 'details': []},
                'dkim': {'status': 'none', 'details': []},
                'dmarc': {'status': 'none', 'details': []},
                'arc': {'status': 'none', 'details': []}
            },
            'delivery_chain': [],
            'network_analysis': {
                'ips': [],
                'domains': [],
                'servers': [],
                'originating_ip': None,
                'reverse_dns': {}
            },
            'content_analysis': {
                'text_parts': [],
                'html_parts': [],
                'attachments': [],
                'urls': [],
                'display_name': '',
                'sender_info': {}
            },
            'extracted_entities': {
                'emails': [],
                'ips': [],
                'domains': [],
                'files': [],
                'phone_numbers': [],
                'credit_cards': [],
                'social_security': [],
                'bitcoin_addresses': []
            },
            'forensic_hashes': {
                'email_complete': {},
                'parts': []
            },
            'security_analysis': {
                'originating_ip_info': {},
                'attachment_details': [],
                'email_preview': {}
            }
        }
        
        # Regex para extração - ADICIONADO NOVOS PADRÕES
        self.regex = {
            'ipv4': re.compile(r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            'ipv6': re.compile(r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b', re.IGNORECASE),
            'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
            'url': re.compile(r'(?:https?|ftp)://[^\s<>"\']+', re.IGNORECASE),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'message_id': re.compile(r'<([^>]+)>'),
            'file_extension': re.compile(r'\.([a-zA-Z0-9]{2,4})(?:[?#]|$)'),
            'phone': re.compile(r'\b(?:\+\d{1,3}[-.]?)?\(?\d{2,3}\)?[-.]?\d{3,4}[-.]?\d{4}\b'),
            'credit_card': re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b'),
            'cpf_cnpj': re.compile(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b|\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b'),
            'bitcoin': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
        }
        
        # Extensões de arquivos comuns
        self.file_extensions = {
            '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.ico', '.webp',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.exe', '.msi', '.bat', '.cmd',
            '.ps1', '.vbs', '.js', '.html', '.htm', '.css', '.json', '.xml',
            '.eml', '.pst', '.ost', '.msg'
        }
    
    def decode_header_value(self, value: str) -> str:
        """Decodifica cabeçalhos MIME."""
        if not value:
            return ""
        
        try:
            decoded = []
            for part, encoding in decode_header(value):
                if isinstance(part, bytes):
                    try:
                        if encoding:
                            text = part.decode(encoding, errors='ignore')
                        else:
                            text = part.decode('utf-8', errors='ignore')
                    except:
                        text = part.decode('latin-1', errors='ignore')
                    decoded.append(text)
                else:
                    decoded.append(str(part))
            return ' '.join(decoded).strip()
        except:
            return str(value)
    
    def extract_metadata(self):
        """Extrai metadados principais - ATUALIZADO para campos adicionais."""
        headers = {}
        for header, value in self.message.items():
            headers[header] = self.decode_header_value(value)
        
        # Extrair Message-ID corretamente
        message_id = headers.get('Message-ID', '')
        if message_id:
            match = self.regex['message_id'].search(message_id)
            if match:
                message_id = match.group(1)
        
        # Extrair Display Name do campo From
        from_header = headers.get('From', '')
        display_name = ''
        email_address = ''
        
        # Tentar extrair nome de exibição do formato "Display Name <email@domain.com>"
        if from_header:
            match = re.match(r'^"?([^"<]+)"?\s*<([^>]+)>$', from_header)
            if match:
                display_name = match.group(1).strip()
                email_address = match.group(2).strip()
            else:
                email_address = from_header
        
        # Extrair destinatários
        to_header = headers.get('To', '')
        cc_header = headers.get('Cc', '')
        bcc_header = headers.get('Bcc', '')
        
        # Extrair IP de origem do primeiro Received header
        originating_ip = None
        for header, value in self.message.items():
            if header.lower() == 'received':
                # Tentar extrair IP do primeiro Received header
                ip_matches = self.regex['ipv4'].findall(value)
                if ip_matches:
                    originating_ip = ip_matches[0]
                    break
        
        self.results['metadata'] = {
            'from': email_address,
            'to': to_header,
            'subject': headers.get('Subject', ''),
            'date': headers.get('Date', ''),
            'message_id': message_id,
            'return_path': headers.get('Return-Path', ''),
            'size_bytes': len(self.email_content),
            'display_name': display_name,
            'sender': headers.get('Sender', ''),
            'cc': cc_header,
            'bcc': bcc_header,
            'in_reply_to': headers.get('In-Reply-To', ''),
            'reply_to': headers.get('Reply-To', ''),
            'originating_ip': originating_ip,
            'x_mailer': headers.get('X-Mailer', ''),
            'content_type': headers.get('Content-Type', ''),
            'mime_version': headers.get('MIME-Version', '')
        }
        
        # Adicionar ao content_analysis para fácil acesso
        self.results['content_analysis']['display_name'] = display_name
        self.results['content_analysis']['sender_info'] = {
            'email': email_address,
            'display_name': display_name
        }
        
        # Adicionar ao network_analysis
        if originating_ip:
            self.results['network_analysis']['originating_ip'] = originating_ip
    
    def analyze_authentication(self):
        """Analisa autenticação com status explícito."""
        headers = {}
        for header, value in self.message.items():
            headers[header] = self.decode_header_value(value)
        
        # SPF
        spf_details = []
        spf_status = 'none'
        
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            if 'received-spf' in header_lower:
                spf_details.append({'header': header_name, 'value': header_value})
                if 'pass' in header_value.lower():
                    spf_status = 'pass'
                elif 'fail' in header_value.lower():
                    spf_status = 'fail'
                elif 'softfail' in header_value.lower():
                    spf_status = 'softfail'
        
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            if 'authentication-results' in header_lower or 'arc-authentication-results' in header_lower:
                if 'spf=pass' in header_value.lower():
                    spf_status = 'pass'
                    spf_details.append({'header': header_name, 'value': header_value})
                elif 'spf=fail' in header_value.lower():
                    spf_status = 'fail'
                    spf_details.append({'header': header_name, 'value': header_value})
                elif 'spf=softfail' in header_value.lower():
                    spf_status = 'softfail'
                    spf_details.append({'header': header_name, 'value': header_value})
        
        # DKIM
        dkim_details = []
        dkim_status = 'none'
        
        if 'DKIM-Signature' in headers:
            dkim_details.append({'header': 'DKIM-Signature', 'value': headers['DKIM-Signature']})
            dkim_status = 'signed'
        
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            if 'authentication-results' in header_lower or 'arc-authentication-results' in header_lower:
                if 'dkim=pass' in header_value.lower():
                    dkim_status = 'pass'
                    dkim_details.append({'header': header_name, 'value': header_value})
                elif 'dkim=fail' in header_value.lower():
                    dkim_status = 'fail'
                    dkim_details.append({'header': header_name, 'value': header_value})
                elif 'dkim=permerror' in header_value.lower():
                    dkim_status = 'fail'
                    dkim_details.append({'header': header_name, 'value': header_value})
                elif 'dkim=none' in header_value.lower():
                    dkim_status = 'none'
                    dkim_details.append({'header': header_name, 'value': header_value})
        
        # DMARC
        dmarc_details = []
        dmarc_status = 'none'
        
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            if 'authentication-results' in header_lower or 'arc-authentication-results' in header_lower:
                if 'dmarc=pass' in header_value.lower():
                    dmarc_status = 'pass'
                    dmarc_details.append({'header': header_name, 'value': header_value})
                elif 'dmarc=fail' in header_value.lower():
                    dmarc_status = 'fail'
                    dmarc_details.append({'header': header_name, 'value': header_value})
                elif 'dmarc=none' in header_value.lower():
                    dmarc_status = 'none'
                    dmarc_details.append({'header': header_name, 'value': header_value})
        
        # ARC
        arc_details = []
        arc_status = 'none'
        
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            if header_lower.startswith('arc-'):
                arc_details.append({'header': header_name, 'value': header_value})
                arc_status = 'present'
        
        # Atualizar resultados
        self.results['authentication']['spf'] = {
            'status': spf_status,
            'details': spf_details
        }
        
        self.results['authentication']['dkim'] = {
            'status': dkim_status,
            'details': dkim_details
        }
        
        self.results['authentication']['dmarc'] = {
            'status': dmarc_status,
            'details': dmarc_details
        }
        
        self.results['authentication']['arc'] = {
            'status': arc_status,
            'details': arc_details
        }
    
    def analyze_delivery_chain(self):
        """Analisa a cadeia de entrega (Received headers)."""
        received_headers = []
        for header, value in self.message.items():
            if header.lower() == 'received':
                received_headers.append(self.decode_header_value(value))
        
        # Processar em ordem reversa (do último para o primeiro)
        delivery_chain = []
        for i, header in enumerate(reversed(received_headers)):
            hop_info = self._parse_received_header(header)
            hop_info['hop_number'] = len(received_headers) - i
            delivery_chain.append(hop_info)
            
            # Extrair IPs e domínios
            self._extract_network_entities(hop_info)
        
        self.results['delivery_chain'] = delivery_chain
    
    def _parse_received_header(self, header: str) -> Dict:
        """Analisa cabeçalho Received detalhadamente."""
        parsed = {
            'raw': header,
            'from_hostname': None,
            'from_ip': None,
            'by_hostname': None,
            'by_ip': None,
            'protocol': None,
            'for_address': None,
            'timestamp': None,
            'with_info': None
        }
        
        # Extrair IPs
        ipv4_matches = self.regex['ipv4'].findall(header)
        ipv6_matches = self.regex['ipv6'].findall(header)
        all_ips = ipv4_matches + ipv6_matches
        
        # "from" pattern
        from_match = re.search(r'from\s+([^\s;]+)', header, re.IGNORECASE)
        if from_match:
            from_value = from_match.group(1)
            parsed['from_hostname'] = from_value
            
            # Tentar extrair IP entre colchetes
            ip_match = re.search(r'\[([^\]]+)\]', from_value)
            if ip_match:
                parsed['from_ip'] = ip_match.group(1)
                # Remover IP do hostname
                parsed['from_hostname'] = from_value.split('[')[0].strip()
            elif from_value in all_ips:
                parsed['from_ip'] = from_value
        
        # "by" pattern
        by_match = re.search(r'by\s+([^\s;]+)', header, re.IGNORECASE)
        if by_match:
            by_value = by_match.group(1)
            parsed['by_hostname'] = by_value
            
            ip_match = re.search(r'\[([^\]]+)\]', by_value)
            if ip_match:
                parsed['by_ip'] = ip_match.group(1)
                parsed['by_hostname'] = by_value.split('[')[0].strip()
            elif by_value in all_ips:
                parsed['by_ip'] = by_value
        
        # "with" pattern
        with_match = re.search(r'with\s+([^\s;]+)', header, re.IGNORECASE)
        if with_match:
            parsed['protocol'] = with_match.group(1)
        
        # "for" pattern
        for_match = re.search(r'for\s+<([^>]+)>', header, re.IGNORECASE)
        if for_match:
            parsed['for_address'] = for_match.group(1)
        else:
            # Tentar outro padrão
            for_match = re.search(r'for\s+([^\s;]+)', header, re.IGNORECASE)
            if for_match:
                parsed['for_address'] = for_match.group(1)
        
        # Extrair timestamp
        date_match = re.search(r';\s*([^;]+)$', header)
        if date_match:
            parsed['timestamp'] = date_match.group(1).strip()
        
        # Extrair informações adicionais (TLS, etc.)
        if 'with' in header.lower():
            parts = header.lower().split('with')
            if len(parts) > 1:
                parsed['with_info'] = parts[1].split(';')[0].strip()
        
        return parsed
    
    def _extract_network_entities(self, hop_info: Dict):
        """Extrai entidades de rede do hop."""
        # Extrair IPs
        ips_to_check = []
        if hop_info.get('from_ip'):
            ips_to_check.append(hop_info['from_ip'])
        if hop_info.get('by_ip'):
            ips_to_check.append(hop_info['by_ip'])
        
        # Extrair também do raw header
        raw_ips = self.regex['ipv4'].findall(hop_info['raw']) + self.regex['ipv6'].findall(hop_info['raw'])
        for ip in raw_ips:
            if ip not in ips_to_check:
                ips_to_check.append(ip)
        
        # Processar cada IP
        for ip in ips_to_check:
            self._classify_and_add_ip(ip)
        
        # Extrair domínios e separar arquivos
        domains_to_check = []
        if hop_info.get('from_hostname'):
            domains_to_check.append(hop_info['from_hostname'])
        if hop_info.get('by_hostname'):
            domains_to_check.append(hop_info['by_hostname'])
        
        # Extrair também do raw header
        raw_domains = self.regex['domain'].findall(hop_info['raw'])
        for domain in raw_domains:
            if domain not in domains_to_check:
                domains_to_check.append(domain)
        
        # Processar cada domínio
        for domain in domains_to_check:
            self._add_domain_or_file(domain)
        
        # Adicionar servidores
        if hop_info.get('by_hostname'):
            server_info = {
                'hostname': hop_info['by_hostname'],
                'ip': hop_info.get('by_ip'),
                'protocol': hop_info.get('protocol'),
                'hop': hop_info.get('hop_number')
            }
            self.results['network_analysis']['servers'].append(server_info)
    
    def _classify_and_add_ip(self, ip: str):
        """Classifica e adiciona IP à análise."""
        if not ip or ip in [i['address'] for i in self.results['network_analysis']['ips']]:
            return
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Determinar tipo
            ip_type = 'IPv4' if ip_obj.version == 4 else 'IPv6'
            
            # Determinar se é público ou privado
            if ip_obj.is_private:
                scope = 'PRIVADO'
                location = 'INTERNO'
            else:
                scope = 'PÚBLICO'
                location = 'EXTERNO'
            
            # Para IPv4, verificar se é localhost
            if ip_type == 'IPv4' and ip in ['127.0.0.1', '127.0.1.1']:
                location = 'LOCAL'
            
            ip_info = {
                'address': ip,
                'type': ip_type,
                'scope': scope,
                'location': location,
                'is_private': ip_obj.is_private,
                'version': ip_obj.version
            }
            
            self.results['network_analysis']['ips'].append(ip_info)
            
            # Adicionar às entidades extraídas
            if ip not in self.results['extracted_entities']['ips']:
                self.results['extracted_entities']['ips'].append(ip)
                
        except ValueError:
            # IP inválido, pular
            pass
    
    def _add_domain_or_file(self, item: str):
        """Adiciona domínio ou arquivo à análise apropriada."""
        if not item:
            return
        
        item_lower = item.lower().strip()
        
        # Verificar se é um arquivo (tem extensão conhecida)
        is_file = False
        for ext in self.file_extensions:
            if item_lower.endswith(ext):
                is_file = True
                if item_lower not in self.results['extracted_entities']['files']:
                    self.results['extracted_entities']['files'].append(item_lower)
                break
        
        # Se não for arquivo, tratar como domínio potencial
        if not is_file:
            # Verificar se parece um domínio (tem ponto e pelo menos 4 caracteres)
            if '.' in item_lower and len(item_lower) >= 4:
                # Filtrar strings que são apenas números com pontos (IPs já tratados)
                if not re.match(r'^\d+\.\d+\.\d+\.\d+$', item_lower):
                    if item_lower not in self.results['network_analysis']['domains']:
                        self.results['network_analysis']['domains'].append(item_lower)
                    
                    # Adicionar às entidades extraídas
                    if item_lower not in self.results['extracted_entities']['domains']:
                        self.results['extracted_entities']['domains'].append(item_lower)
    
    def analyze_content(self):
        """Analisa conteúdo e anexos - ATUALIZADO para detalhes de anexos."""
        if self.message.is_multipart():
            for part in self.message.walk():
                self._analyze_content_part(part)
        else:
            self._analyze_content_part(self.message)
        
        # Processar detalhes de anexos para security_analysis
        attachments = self.results['content_analysis']['attachments']
        attachment_details = []
        
        for att in attachments:
            if isinstance(att, dict):
                att_details = att.copy()
                
                # Adicionar hashes adicionais
                if 'sha256' in att:
                    att_details['sha_1'] = self._calculate_sha1(att.get('content_bytes'))
                
                # Detectar tipo de arquivo
                filename = att.get('filename', '')
                if filename:
                    ext = os.path.splitext(filename)[1].lower()
                    att_details['file_type'] = self._get_file_type_description(ext)
                
                attachment_details.append(att_details)
        
        self.results['security_analysis']['attachment_details'] = attachment_details
    
    def _analyze_content_part(self, part):
        """Analisa uma parte do conteúdo - ATUALIZADO."""
        content_type = part.get_content_type()
        filename = part.get_filename()
        content_bytes = part.get_payload(decode=True)
        
        if not content_bytes or content_type.startswith('multipart/'):
            return
        
        charset = part.get_content_charset() or 'utf-8'
        decoded_filename = self.decode_header_value(filename) if filename else None
        
        # Calcular todos os hashes
        md5_hash = hashlib.md5(content_bytes).hexdigest()
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        
        part_info = {
            'content_type': content_type,
            'filename': decoded_filename,
            'size_bytes': len(content_bytes),
            'md5': md5_hash,
            'sha256': sha256_hash,
            'encoding': part.get('content-transfer-encoding', '').lower(),
            'content_bytes': content_bytes if content_type.startswith('text/') else None  # Guardar para análise
        }
        
        # Adicionar hash da parte
        part_name = decoded_filename or f"part_{len(self.results['forensic_hashes']['parts'])}"
        self.results['forensic_hashes']['parts'].append({
            'filename': part_name,
            'content_type': content_type,
            'sha256': sha256_hash,
            'md5': md5_hash,
            'size_bytes': part_info['size_bytes']
        })
        
        # Classificar parte
        if content_type.startswith('text/'):
            try:
                text = content_bytes.decode(charset, errors='replace')
                part_info['text_preview'] = text[:1000]  # Prévia maior
                part_info['character_count'] = len(text)
                part_info['word_count'] = len(text.split())
                
                # Extrair entidades do texto
                self._extract_entities_from_text(text)
                
                if content_type == 'text/plain':
                    self.results['content_analysis']['text_parts'].append(part_info)
                elif content_type == 'text/html':
                    self.results['content_analysis']['html_parts'].append(part_info)
                    
                    # Extrair URLs específicas de HTML
                    self._extract_urls_from_html(text, part_name)
                        
            except:
                pass
        
        elif decoded_filename:  # É um anexo
            attachment_info = part_info.copy()
            # Não guardar content_bytes para anexos binários
            if 'content_bytes' in attachment_info:
                del attachment_info['content_bytes']
            
            self.results['content_analysis']['attachments'].append(attachment_info)
            
            # Adicionar à lista de arquivos
            if decoded_filename.lower() not in self.results['extracted_entities']['files']:
                self.results['extracted_entities']['files'].append(decoded_filename.lower())
    
    def _calculate_sha1(self, content_bytes):
        """Calcula hash SHA-1."""
        if content_bytes:
            return hashlib.sha1(content_bytes).hexdigest()
        return None
    
    def _get_file_type_description(self, extension: str) -> str:
        """Retorna descrição do tipo de arquivo."""
        extension = extension.lower()
        
        type_map = {
            '.pdf': 'PDF Document',
            '.doc': 'Word Document',
            '.docx': 'Word Document',
            '.xls': 'Excel Spreadsheet',
            '.xlsx': 'Excel Spreadsheet',
            '.ppt': 'PowerPoint Presentation',
            '.pptx': 'PowerPoint Presentation',
            '.txt': 'Text File',
            '.zip': 'ZIP Archive',
            '.rar': 'RAR Archive',
            '.7z': '7-Zip Archive',
            '.exe': 'Executable File',
            '.msi': 'Windows Installer',
            '.js': 'JavaScript File',
            '.html': 'HTML Document',
            '.htm': 'HTML Document',
            '.eml': 'Email File',
            '.msg': 'Outlook Message',
            '.pst': 'Outlook Data File'
        }
        
        return type_map.get(extension, f'{extension.upper()[1:]} File' if extension else 'Unknown')
    
    def _extract_urls_from_html(self, html_text: str, source: str):
        """Extrai URLs de HTML de forma mais completa."""
        # Encontrar todas as ocorrências de URLs
        url_pattern = r'(?:https?|ftp)://[^\s<>"\']+'
        
        # Também procurar por URLs em atributos HTML
        html_patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'url\(["\']?([^"\'()]+)["\']?\)'
        ]
        
        all_urls = []
        
        # Extrair URLs do padrão simples
        simple_urls = re.findall(url_pattern, html_text, re.IGNORECASE)
        all_urls.extend(simple_urls)
        
        # Extrair URLs de atributos HTML
        for pattern in html_patterns:
            matches = re.findall(pattern, html_text, re.IGNORECASE)
            for match in matches:
                # Se a URL não começar com http/https/ftp, pode ser relativa
                if match.startswith(('http://', 'https://', 'ftp://', '//')):
                    all_urls.append(match)
                elif match.startswith('/'):
                    # URL relativa ao domínio - vamos manter como está
                    all_urls.append(match)
        
        # Processar URLs únicas
        for url in set(all_urls):
            # Se a URL for muito longa, vamos mantê-la completa no JSON
            # mas talvez mostrar uma versão truncada na saída
            url_info = {
                'url': url,
                'source': source,
                'length': len(url)
            }
            self.results['content_analysis']['urls'].append(url_info)
            
            # Extrair domínio/arquivo da URL
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    self._add_domain_or_file(parsed.netloc)
                # Extrair possíveis arquivos do path
                if parsed.path:
                    path_lower = parsed.path.lower()
                    for ext in self.file_extensions:
                        if path_lower.endswith(ext):
                            filename = os.path.basename(path_lower)
                            if filename not in self.results['extracted_entities']['files']:
                                self.results['extracted_entities']['files'].append(filename)
                            break
            except:
                pass
    
    def _extract_entities_from_text(self, text: str):
        """Extrai entidades (emails, IPs, domínios) do texto - ATUALIZADO."""
        # Emails
        emails = self.regex['email'].findall(text)
        for email_addr in emails:
            email_lower = email_addr.lower()
            if email_lower not in self.results['extracted_entities']['emails']:
                self.results['extracted_entities']['emails'].append(email_lower)
        
        # IPs
        ips = self.regex['ipv4'].findall(text) + self.regex['ipv6'].findall(text)
        for ip in ips:
            self._classify_and_add_ip(ip)
        
        # Telefones
        phones = self.regex['phone'].findall(text)
        for phone in phones:
            if phone not in self.results['extracted_entities']['phone_numbers']:
                self.results['extracted_entities']['phone_numbers'].append(phone)
        
        # Cartões de crédito
        credit_cards = self.regex['credit_card'].findall(text)
        for card in credit_cards:
            if card not in self.results['extracted_entities']['credit_cards']:
                self.results['extracted_entities']['credit_cards'].append(card)
        
        # CPF/CNPJ
        cpf_cnpj = self.regex['cpf_cnpj'].findall(text)
        for doc in cpf_cnpj:
            if doc not in self.results['extracted_entities']['social_security']:
                self.results['extracted_entities']['social_security'].append(doc)
        
        # Endereços Bitcoin
        bitcoin = self.regex['bitcoin'].findall(text)
        for addr in bitcoin:
            if addr not in self.results['extracted_entities']['bitcoin_addresses']:
                self.results['extracted_entities']['bitcoin_addresses'].append(addr)
        
        # Domínios e arquivos
        potential_items = re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?', text)
        for item in potential_items:
            self._add_domain_or_file(item.split('/')[0])
    
    def calculate_hashes(self):
        """Calcula hashes forenses."""
        # Hash do email completo
        email_hash_sha256 = hashlib.sha256(self.email_content).hexdigest()
        email_hash_md5 = hashlib.md5(self.email_content).hexdigest()
        
        self.results['forensic_hashes']['email_complete'] = {
            'sha256': email_hash_sha256,
            'md5': email_hash_md5,
            'size_bytes': len(self.email_content)
        }
    
    def analyze(self):
        """Executa análise completa."""
        self.extract_metadata()
        self.analyze_authentication()
        self.analyze_delivery_chain()
        self.analyze_content()
        self.calculate_hashes()
        
        # Tentar fazer rDNS lookup para o IP de origem
        originating_ip = self.results['network_analysis'].get('originating_ip')
        if originating_ip:
            try:
                hostname = socket.gethostbyaddr(originating_ip)[0]
                self.results['network_analysis']['reverse_dns'][originating_ip] = hostname
            except:
                self.results['network_analysis']['reverse_dns'][originating_ip] = None
        
        return self.results


# ============ ENHANCED EMAIL ANALYZER ============
class EnhancedEmailAnalyzer:
    @staticmethod
    def analyze_email(data: Dict) -> Dict:
        """Análise completa e otimizada do email - ATUALIZADO para novos campos."""
        try:
            metadata = data.get('metadata', {})
            auth = data.get('authentication', {})
            content = data.get('content_analysis', {})
            network = data.get('network_analysis', {})
            entities = data.get('extracted_entities', {})
            forensic = data.get('forensic_hashes', {})
            
            # Análise de autenticação
            def get_auth_details(auth_data, protocol):
                if not isinstance(auth_data, dict):
                    return {'status': 'none', 'result': '', 'domain': '', 'details': []}
                
                proto_data = auth_data.get(protocol, {})
                if not isinstance(proto_data, dict):
                    return {'status': 'none', 'result': '', 'domain': '', 'details': []}
                
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
                                    status = 'present'
                                    break
                
                if status not in ['pass', 'fail', 'none', 'present', 'temperror', 'softfail']:
                    status = 'none'
                
                # Extrair resultados do ARC
                if protocol == 'arc' and status != 'none':
                    arc_result = {
                        'seal': {},
                        'signature': {},
                        'ams': {}
                    }
                    
                    details_list = proto_data.get('details', [])
                    if isinstance(details_list, list):
                        for detail in details_list:
                            if isinstance(detail, dict):
                                header = detail.get('header', '')
                                value = detail.get('value', '')
                                
                                if 'arc-seal' in header.lower():
                                    arc_result['seal'] = {'header': header, 'value': value}
                                elif 'arc-signature' in header.lower():
                                    arc_result['signature'] = {'header': header, 'value': value}
                                elif 'arc-authentication-results' in header.lower() or 'arc-ams' in header.lower():
                                    arc_result['ams'] = {'header': header, 'value': value}
                    
                    return {
                        'status': status,
                        'result': proto_data.get('result', '') if isinstance(proto_data.get('result'), str) else '',
                        'domain': proto_data.get('domain', '') if isinstance(proto_data.get('domain'), str) else '',
                        'details': proto_data.get('details', []) if isinstance(proto_data.get('details'), list) else [],
                        'arc_result': arc_result
                    }
                else:
                    return {
                        'status': status,
                        'result': proto_data.get('result', '') if isinstance(proto_data.get('result'), str) else '',
                        'domain': proto_data.get('domain', '') if isinstance(proto_data.get('domain'), str) else '',
                        'details': proto_data.get('details', []) if isinstance(proto_data.get('details'), list) else []
                    }
            
            auth_analysis = {
                'spf': get_auth_details(auth, 'spf'),
                'dkim': get_auth_details(auth, 'dkim'),
                'dmarc': get_auth_details(auth, 'dmarc'),
                'arc': get_auth_details(auth, 'arc')
            }
            
            # Análise de conteúdo - ATUALIZADA
            urls = content.get('urls', [])
            if not isinstance(urls, list):
                urls = []
            
            attachments = content.get('attachments', [])
            if not isinstance(attachments, list):
                attachments = []
            
            # Processar URLs para análise
            suspicious_domains = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
            shortened_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'buff.ly']
            
            suspicious_urls = 0
            shortened_urls = 0
            url_list = []
            
            for url_obj in urls[:100]:
                if isinstance(url_obj, dict):
                    url = url_obj.get('url', '')
                    if isinstance(url, str):
                        url_lower = url.lower()
                        url_list.append(url)
                        
                        if any(domain in url_lower for domain in suspicious_domains):
                            suspicious_urls += 1
                        if any(service in url_lower for service in shortened_services):
                            shortened_urls += 1
                elif isinstance(url_obj, str):
                    url_list.append(url_obj)
                    url_lower = url_obj.lower()
                    if any(domain in url_lower for domain in suspicious_domains):
                        suspicious_urls += 1
                    if any(service in url_lower for service in shortened_services):
                        shortened_urls += 1
            
            # Informações do remetente
            sender_info = content.get('sender_info', {})
            display_name = content.get('display_name', '')
            
            content_analysis = {
                'text_parts': int(content.get('text_parts', 0)) if isinstance(content.get('text_parts'), (int, float)) else 0,
                'html_parts': int(content.get('html_parts', 0)) if isinstance(content.get('html_parts'), (int, float)) else 0,
                'attachments': attachments,
                'urls': url_list[:50],
                'languages': content.get('languages', []) if isinstance(content.get('languages'), list) else [],
                'character_count': int(content.get('character_count', 0)) if isinstance(content.get('character_count'), (int, float)) else 0,
                'word_count': int(content.get('word_count', 0)) if isinstance(content.get('word_count'), (int, float)) else 0,
                'suspicious_urls': suspicious_urls,
                'shortened_urls': shortened_urls,
                'display_name': display_name,
                'sender_info': sender_info
            }
            
            # Análise de rede - ATUALIZADA
            network_ips = network.get('ips', [])
            if not isinstance(network_ips, list):
                network_ips = []
            
            network_domains = network.get('domains', [])
            if not isinstance(network_domains, list):
                network_domains = []
            
            network_analysis = {
                'ips': network_ips[:100],
                'domains': list(set(network_domains))[:100],
                'servers': network.get('servers', [])[:50] if isinstance(network.get('servers'), list) else [],
                'geolocations': network.get('geolocations', [])[:50] if isinstance(network.get('geolocations'), list) else [],
                'asn_info': network.get('asn_info', [])[:50] if isinstance(network.get('asn_info'), list) else [],
                'originating_ip': network.get('originating_ip'),
                'reverse_dns': network.get('reverse_dns', {})
            }
            
            # Análise de entidades
            def get_entities_list(entities_data, key, limit=100):
                data = entities_data.get(key, [])
                if not isinstance(data, list):
                    return []
                return list(set([str(item) for item in data[:limit] if item]))
            
            entities_analysis = {
                'emails': get_entities_list(entities, 'emails', 100),
                'ips': get_entities_list(entities, 'ips', 100),
                'domains': get_entities_list(entities, 'domains', 100),
                'files': get_entities_list(entities, 'files', 50),
                'phone_numbers': get_entities_list(entities, 'phone_numbers', 50),
                'credit_cards': get_entities_list(entities, 'credit_cards', 20),
                'social_security': get_entities_list(entities, 'social_security', 20),
                'bitcoin_addresses': get_entities_list(entities, 'bitcoin_addresses', 20)
            }
            
            # Detalhes de anexos para security_analysis
            security_analysis = data.get('security_analysis', {})
            
            # Indicadores de segurança
            security_indicators = {
                'malicious_patterns': [],
                'social_engineering': [],
                'suspicious_keywords': [],
                'reputation_score': 0,
                'risk_level': 'low',
                'attachment_analysis': security_analysis.get('attachment_details', []),
                'originating_ip_info': security_analysis.get('originating_ip_info', {})
            }
            
            # Calcular score de risco
            risk_score = 0
            
            # Verificar palavras-chave de phishing
            subject = metadata.get('subject', '')
            if isinstance(subject, str):
                subject_lower = subject.lower()
                
                phishing_keywords = ['urgente', 'imediato', 'senha', 'verificar', 'segurança', 
                                    'suspensão', 'bloqueio', 'conta', 'login', 'banco',
                                    'pagamento', 'fatura', 'dívida', 'multa', 'urgent',
                                    'atualizar', 'confirmar', 'clique aqui', 'oferta especial',
                                    'crítico', 'crítico', 'alerta', 'confirme', 'atualize']
                
                found_keywords = []
                for keyword in phishing_keywords:
                    if keyword in subject_lower:
                        found_keywords.append(keyword)
                        risk_score += 5
                
                if found_keywords:
                    security_indicators['suspicious_keywords'] = found_keywords
            
            # Adicionar pontos por URLs suspeitas
            risk_score += suspicious_urls * 10
            risk_score += shortened_urls * 5
            
            # Adicionar pontos por falhas de autenticação
            for protocol in ['spf', 'dkim', 'dmarc']:
                if auth_analysis[protocol]['status'] == 'fail':
                    risk_score += 15
                elif auth_analysis[protocol]['status'] == 'none':
                    risk_score += 5
            
            # Pontos por anexos executáveis
            for att in attachments:
                if isinstance(att, dict):
                    filename = att.get('filename', '').lower()
                    if any(ext in filename for ext in ['.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs']):
                        risk_score += 20
            
            # Determinar nível de risco
            if risk_score >= 40:
                security_indicators['risk_level'] = 'high'
            elif risk_score >= 20:
                security_indicators['risk_level'] = 'medium'
            else:
                security_indicators['risk_level'] = 'low'
            
            security_indicators['reputation_score'] = max(0, 100 - min(risk_score, 100))
            
            return {
                'authentication': auth_analysis,
                'content_analysis': content_analysis,
                'network_analysis': network_analysis,
                'entities': entities_analysis,
                'forensic': forensic if isinstance(forensic, dict) else {},
                'security_indicators': security_indicators,
                'sender_display_info': {
                    'display_name': display_name,
                    'sender_email': metadata.get('from', ''),
                    'sender_full': metadata.get('sender', '')
                }
            }
        except Exception as e:
            print(f"[ERRO] Na análise de email: {str(e)}")
            traceback.print_exc()
            return {
                'authentication': {
                    'spf': {'status': 'none', 'result': '', 'domain': '', 'details': []},
                    'dkim': {'status': 'none', 'result': '', 'domain': '', 'details': []},
                    'dmarc': {'status': 'none', 'result': '', 'domain': '', 'details': []},
                    'arc': {'status': 'none', 'result': '', 'domain': '', 'details': [], 'arc_result': {}}
                },
                'content_analysis': {
                    'text_parts': 0,
                    'html_parts': 0,
                    'attachments': [],
                    'urls': [],
                    'languages': [],
                    'character_count': 0,
                    'word_count': 0,
                    'suspicious_urls': 0,
                    'shortened_urls': 0,
                    'display_name': '',
                    'sender_info': {}
                },
                'network_analysis': {
                    'ips': [],
                    'domains': [],
                    'servers': [],
                    'geolocations': [],
                    'asn_info': [],
                    'originating_ip': None,
                    'reverse_dns': {}
                },
                'entities': {
                    'emails': [],
                    'ips': [],
                    'domains': [],
                    'files': [],
                    'phone_numbers': [],
                    'credit_cards': [],
                    'social_security': [],
                    'bitcoin_addresses': []
                },
                'forensic': {},
                'security_indicators': {
                    'malicious_patterns': [],
                    'social_engineering': [],
                    'suspicious_keywords': [],
                    'reputation_score': 100,
                    'risk_level': 'low',
                    'attachment_analysis': [],
                    'originating_ip_info': {}
                },
                'sender_display_info': {
                    'display_name': '',
                    'sender_email': '',
                    'sender_full': ''
                }
            }


def extract_tags(data: Dict) -> List[str]:
    """Extrai tags otimizadas para busca - ATUALIZADA."""
    tags = []
    
    try:
        # Tags de autenticação
        auth = data.get('authentication', {})
        if isinstance(auth, dict):
            for protocol in ['spf', 'dkim', 'dmarc', 'arc']:
                protocol_data = auth.get(protocol, {})
                if isinstance(protocol_data, dict):
                    status = protocol_data.get('status', 'none')
                    if status in ['pass', 'fail', 'none', 'present']:
                        tags.append(f"auth_{protocol}_{status}")
        
        # Tags de conteúdo
        content = data.get('content_analysis', {})
        if isinstance(content, dict):
            attachments = content.get('attachments', [])
            if isinstance(attachments, list) and len(attachments) > 0:
                tags.append('has_attachments')
            elif isinstance(attachments, (int, float)) and attachments > 0:
                tags.append('has_attachments')
            
            urls = content.get('urls', [])
            if isinstance(urls, list) and len(urls) > 0:
                tags.append('has_urls')
            
            html_parts = content.get('html_parts', 0)
            if isinstance(html_parts, (int, float)) and html_parts > 0:
                tags.append('has_html')
            
            # Tags baseadas no nome de exibição
            display_name = content.get('display_name', '')
            if display_name and isinstance(display_name, str):
                name_clean = re.sub(r'[^a-zA-Z0-9]', '_', display_name.lower())
                if name_clean:
                    tags.append(f"display_{name_clean[:30]}")
        
        # Tags baseadas em domínio
        metadata = data.get('metadata', {})
        if isinstance(metadata, dict):
            from_email = metadata.get('from', '')
            if isinstance(from_email, str) and '@' in from_email:
                domain = from_email.split('@')[-1].lower()
                tags.append(f"domain_{domain}")
            
            # Tags de IP de origem
            originating_ip = metadata.get('originating_ip')
            if originating_ip:
                tags.append(f"orig_ip_{originating_ip}")
        
        # Tags de risco
        subject = metadata.get('subject', '')
        if isinstance(subject, str):
            subject_lower = subject.lower()
            risky_terms = ['urgente', 'senha', 'banco', 'pagamento', 'fatura', 'crítico', 'alerta']
            if any(term in subject_lower for term in risky_terms):
                tags.append('potential_phishing')
        
        return list(set(tags))
    except Exception as e:
        print(f"[ERRO] Ao extrair tags: {str(e)}")
        return []