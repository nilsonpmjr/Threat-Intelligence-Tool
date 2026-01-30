from datetime import datetime
from zoneinfo import ZoneInfo
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.text import Text
from rich import box
from rich.align import Align
from rich.columns import Columns
from logging_config import get_logger

logger = get_logger(__name__)

class ReportGenerator:
    """
    Handles accumulation and formatting of threat intelligence results using Rich.
    Supports printable reports and dashboard views.
    """
    
    

    TRANS = {
        'pt': {
            'title': "RELATÓRIO DE INTELIGÊNCIA DE AMEAÇAS",
            'target': "Alvo",
            'type': "Tipo",
            'timestamp': "Data/Hora",
            'verdict': "VEREDITO",
            'high_risk': "ALTO RISCO",
            'safe': "SEGURO",
            'suspicious': "SUSPEITO",
            'unknown': "DESCONHECIDO",
            'sources_flagged': "Fontes Alertaram",
            'end_report': "Fim do Relatório",
            
            # Service Specific
            'score': "Pontuação",
            'vendors': "Fornecedores",
            'last_analysis': "Última Análise",
            'confidence': "Confiança",
            'reports': "Denúncias",
            'usage_type': "Tipo de Uso",
            'status': "Status",
            'class': "Classe",
            'class': "Classe",
            'ports': "Portas Abertas",
            'os': "Sistema Operacional",
            'vulns': "Vulnerabilidades",
            'pulses': "Pulsos de Ameaça",
            'total_scans': "Total de Escaneamentos",
            'malicious': "Malicioso",
            'country': "País",
            'city': "Cidade",
            'isp': "ISP",
            'asn': "ASN",
            'org': "Organização",
            'domain': "Domínio",
            # Explanations
            'pulse_desc': "Eventos de ameaça reportados pela comunidade",
            'riot_desc': "IPs benignos comuns (Rule It Out - Ex: Google DNS, CDNs)",
            'noise_desc': "Verificado escaneando a internet (Scanner de fundo)",
            
            # Tag Descriptions (Common samples)
            'tags': {
                'via-tor': 'Comunica-se via rede Tor (Anonimato)',
                'detect-debug-environment': 'Tenta detectar se está sendo analisado/depurado',
                'direct-cpu-clock-access': 'Acesso direto ao relógio da CPU (evasão/timing)',
                'long-sleeps': 'Dorme por longos períodos para evitar análise dinâmica',
                'attachment': 'Distribuído como anexo de e-mail',
                'p2p-communication': 'Usa redes Peer-to-Peer',
                'checking-user-input': 'Captura ou verifica entrada do usuário (Keylogger/Spyware)',
                'run-from-memory': 'Executa apenas na memória (Fileless malware)',
                'persistence': 'Tenta se manter no sistema após reinicialização'
            },
            'filename': "Nome do Arquivo",
            'network': "Rede (CIDR)",
            'votes': "Votos da Comunidade",
            'last_seen': "Visto por Último",
            'last_reported': "Último Reporte",
            'hostnames': "Hostnames",
            'actor': "Ator/Grupo",
            'bot': "Bot/Malware",
            'page_title': "Título da Página",
            'server': "Servidor",
            'pulse_names': "Pulsos Recentes"
        },
        'en': {
            'title': "THREAT INTELLIGENCE REPORT",
            'target': "Target",
            'type': "Type",
            'timestamp': "Timestamp",
            'verdict': "VERDICT",
            'high_risk': "HIGH RISK",
            'safe': "SAFE",
            'suspicious': "SUSPICIOUS",
            'unknown': "UNKNOWN",
            'sources_flagged': "Sources Flagged",
            'end_report': "End of Report",
            
            # Service Specific
            'score': "Score",
            'vendors': "Vendors",
            'last_analysis': "Last Analysis",
            'confidence': "Confidence Score",
            'reports': "Reports",
            'usage_type': "Usage Type",
            'status': "Status",
            'class': "Class",
            'ports': "Open Ports",
            'os': "OS",
            'vulns': "Vulns",
            'pulses': "Threat Pulses",
            'total_scans': "Total Scans",
            'malicious': "Malicious",
            'country': "Country",
            'city': "City",
            'isp': "ISP",
            'asn': "ASN",
            'org': "Organization",
            'domain': "Domain",
             # Explanations
            'pulse_desc': "Community reported threat events",
            'riot_desc': "Common benign IPs (Rule It Out - e.g. Google DNS, CDNs)",
            'noise_desc': "Verified scanning the internet (Background Noise)",
            
             # Tag Descriptions
            'tags': {
                'via-tor': 'Communicates via Tor network (Anonymity)',
                'detect-debug-environment': 'Attempts to detect analysis/debugging environment',
                'direct-cpu-clock-access': 'Direct CPU clock access (Evasion/Timing)',
                'long-sleeps': 'Sleeps for long periods to evade dynamic analysis',
                'attachment': 'Distributed as email attachment',
                'p2p-communication': 'Uses Peer-to-Peer networks',
                'checking-user-input': 'Captures or checks user input (Keylogger/Spyware)',
                'run-from-memory': 'Executes from memory only (Fileless malware)',
                'persistence': 'Attempts to persist after reboot'
            },
            'filename': "Filename",
            'network': "Network (CIDR)",
            'votes': "Community Votes",
            'last_seen': "Last Seen",
            'last_reported': "Last Reported",
            'hostnames': "Hostnames",
            'actor': "Actor",
            'bot': "Bot/Malware",
            'page_title': "Page Title",
            'server': "Server",
            'pulse_names': "Recent Pulses"
        }
    }
    
    

    COUNTRY_MAP = {
        'US': 'United States', 'CN': 'China', 'RU': 'Russia', 'BR': 'Brazil', 
        'DE': 'Germany', 'GB': 'United Kingdom', 'FR': 'France', 'NL': 'Netherlands',
        'IN': 'India', 'SG': 'Singapore', 'JP': 'Japan', 'CA': 'Canada', 'AU': 'Australia',
        'KR': 'South Korea', 'VN': 'Vietnam', 'ID': 'Indonesia', 'TR': 'Turkey'
    }

    def __init__(self, target, lang='pt'):
        self.target = target
        self.lang = lang if lang in self.TRANS else 'en'
        self.t = self.TRANS[self.lang]
        self.results = {}
        self.timestamp = datetime.now(ZoneInfo("America/Sao_Paulo")).strftime("%Y-%m-%d %H:%M:%S %Z")
        self.console = Console()
        self.risk_counter = 0
        self.total_sources = 0

    def _get_country_name(self, code):
        """Helper to get full country name from code."""
        if not code: return "N/A"
        return self.COUNTRY_MAP.get(code.upper(), code)
    
    def _get_tag_desc(self, tag):
        """Helper to get description for a tag."""
        return self.t.get('tags', {}).get(tag)

    def add_result(self, service_name, data):
        """Adds a result and updates risk metrics."""
        if data is None:
            data = {"error": "API returned no data (Check logs or API Status)"}
            
        self.results[service_name] = data
        self.total_sources += 1
        
        
        is_risky = False
        if "error" in data:
            return

        if service_name == 'virustotal':
            malicious = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            if malicious >= 3: is_risky = True # Threshold to filter FPs
        elif service_name == 'abuseipdb':
            if data.get('data', {}).get('abuseConfidenceScore', 0) >= 25: is_risky = True
        elif service_name == 'alienvault':
            if data.get('pulse_info', {}).get('count', 0) > 0: is_risky = True
        elif service_name == 'urlscan':
            if data.get('data', {}).get('verdict', {}).get('score', 0) > 0: is_risky = True
        elif service_name == 'greynoise':
             if data.get('classification') == 'malicious': is_risky = True
        
        if is_risky:
            self.risk_counter += 1

    def _get_verdict_panel(self):
        """Generates the verdict panel."""
        flagged = f"{self.risk_counter}/{self.total_sources}"
        
        if self.risk_counter >= 2:
            color = "red"
            text = f"🚨 {self.t['verdict']}: {self.t['high_risk']} ({flagged} {self.t['sources_flagged']})"
        elif self.risk_counter == 1:
            color = "yellow"
            text = f"⚠️  {self.t['verdict']}: {self.t['suspicious']} ({flagged} {self.t['sources_flagged']})"
        else:
            color = "green"
            text = f"🛡️  {self.t['verdict']}: {self.t['safe']} ({flagged} {self.t['sources_flagged']})"
            
        return Panel(Align.center(f"[bold {color}]{text}[/]"), border_style=color)

    def _format_service_content(self, service, data):
        """Formats the inner content for a service."""
        if "error" in data:
            return f"[red]Error: {data['error']}[/]"



        if "_meta_error" in data:
            err = data["_meta_error"]
            msg = data["_meta_msg"]
            if err == "not_found":
                return f"[dim white]ℹ️  {msg}[/]"
            elif err == "forbidden":
                return f"[yellow]⚠️  {msg}[/]"
            else:
                return f"[red]❌ {msg}[/]"

        lines = []
        
        if service == 'virustotal':
            try:
                attrs = data.get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())
                
                color = "red" if malicious > 0 else "green"
                lines.append(f"• {self.t['score']}: [{color}]{malicious}/{total} {self.t['vendors']}[/]")
                
                # Community Votes
                votes = attrs.get('total_votes', {})
                if votes:
                    h = votes.get('harmless', 0)
                    m = votes.get('malicious', 0)
                    lines.append(f"• {self.t['votes']}: [green]👍 {h}[/] / [red]👎 {m}[/]")
                
                # Last Scan
                last_scan = attrs.get('last_analysis_date')
                if last_scan:
                    dt = datetime.fromtimestamp(last_scan).strftime('%Y-%m-%d')
                    lines.append(f"• {self.t['last_analysis']}: {dt}")

                # Network CIDR (IP specific)
                network = attrs.get('network')
                if network:
                     lines.append(f"• {self.t['network']}: {network}")
                
                # Filename logic
                filename = attrs.get('meaningful_name')
                if not filename:
                    names = attrs.get('names')
                    if names and len(names) > 0: filename = names[0]
                
                if filename:
                    lines.append(f"• {self.t['filename']}: {filename}")
                
                if 'country' in attrs: lines.append(f"• {self.t['country']}: {self._get_country_name(attrs['country'])}")
                if 'as_owner' in attrs: lines.append(f"• {self.t['org']}: {attrs['as_owner']}")
                
                # Tags
                tags = attrs.get('tags', [])

                if tags:
                    lines.append(f"• Tags: [dim]{', '.join(tags[:5])}[/]")
                    # Show descriptions for known tags
                    for tag in tags[:5]:
                        desc = self._get_tag_desc(tag)
                        if desc:
                             lines.append(f"  [dim italic]↳ {tag}: {desc}[/]")
            except Exception as e:
                logger.error(f"Error parsing VirusTotal data: {e}")
                lines.append(f"[yellow]Error parsing data[/]")

        elif service == 'abuseipdb':
            try:
                d = data.get('data', {})
                score = d.get('abuseConfidenceScore', 0)
                color = "red" if score > 0 else "green"
                lines.append(f"• {self.t['confidence']}: [{color}]{score}%[/]")
                lines.append(f"• {self.t['reports']}: {d.get('totalReports', 0)}")
                
                # Last Reported
                last_reported = d.get('lastReportedAt')
                if last_reported:
                     # Format: 2024-01-01T12:00:00+00:00 -> 2024-01-01
                     try:
                         dt = datetime.fromisoformat(last_reported).strftime('%Y-%m-%d')
                         lines.append(f"• {self.t['last_reported']}: {dt}")
                     except: pass

                lines.append(f"• {self.t['usage_type']}: {d.get('usageType', 'N/A')}")
                if 'countryCode' in d: lines.append(f"• {self.t['country']}: {self._get_country_name(d['countryCode'])}")
                if 'isp' in d: lines.append(f"• {self.t['isp']}: {d['isp']}")
                if 'domain' in d: lines.append(f"• {self.t['domain']}: {d['domain']}")
            except Exception as e:
                logger.error(f"Error parsing AbuseIPDB data: {e}")
                lines.append(f"[yellow]Error parsing data[/]")

        elif service == 'shodan':
            try:
                lines.append(f"• {self.t['os']}: {data.get('os', 'N/A')}")
                lines.append(f"• {self.t['org']}: {data.get('org', 'N/A')}")
                if 'city' in data and 'country_name' in data:
                    lines.append(f"• {self.t['city']}/{self.t['country']}: {data.get('city')}, {data.get('country_name')}")
                
                # Hostnames
                hostnames = data.get('hostnames', [])
                if hostnames:
                    lines.append(f"• {self.t['hostnames']}: {', '.join(hostnames[:3])}")
                
                # Last Update
                last_update = data.get('last_update')
                if last_update:
                    try:
                        # Format: 2024-01-01T12:00:00 -> 2024-01-01
                        dt = datetime.fromisoformat(last_update.split('.')[0]).strftime('%Y-%m-%d')
                        lines.append(f"• {self.t['last_analysis']}: {dt}")
                    except: pass

                ports = data.get('ports', [])
                lines.append(f"• {self.t['ports']}: {', '.join(map(str, ports)) if ports else 'None'}")
                if 'vulns' in data:
                    lines.append(f"• {self.t['vulns']}: [red]{len(data['vulns'])} detected[/]")
            except Exception as e:
                logger.error(f"Error parsing Shodan data: {e}")
                lines.append(f"[yellow]Error parsing data[/]")

        elif service == 'alienvault':
            try:
                pulse_info = data.get('pulse_info', {})
                count = pulse_info.get('count', 0)
                color = "red" if count > 0 else "green"
                lines.append(f"• {self.t['pulses']}: [{color}]{count}[/]")
                lines.append(f"  [dim italic]↳ {self.t['pulse_desc']}[/]")
                
                # Recent Pulse Names
                pulses = pulse_info.get('pulses', [])
                if pulses:
                    names = [p.get('name') for p in pulses[:3]]
                    lines.append(f"• {self.t['pulse_names']}: [dim]{', '.join(names)}[/]")
                
                if 'country_name' in data: lines.append(f"• {self.t['country']}: {data.get('country_name')}")
                if 'city' in data: lines.append(f"• {self.t['city']}: {data.get('city')}")
            except Exception as e:
                logger.error(f"Error parsing AlienVault data: {e}")
                lines.append(f"[yellow]Error parsing data[/]")
            
        elif service == 'greynoise':
            try:
                noise = data.get('noise', False)
                riot = data.get('riot', False)
                lines.append(f"• Noise: {'[red]Yes[/]' if noise else '[green]No[/]'}")
                if noise: lines.append(f"  [dim italic]↳ {self.t['noise_desc']}[/]")
                
                lines.append(f"• RIOT: {'[green]Yes[/]' if riot else '[blue]No[/]'}")
                lines.append(f"  [dim italic]↳ {self.t['riot_desc']}[/]")
                
                lines.append(f"• {self.t['class']}: {data.get('classification', 'unknown')}")
                
                # Actor/Bot
                actor = data.get('actor')
                if actor and actor != 'unknown': lines.append(f"• {self.t['actor']}: {actor}")
                
                bot = data.get('bot')
                if bot: lines.append(f"• {self.t['bot']}: {bot}")
                
                last_seen = data.get('last_seen')
                if last_seen: lines.append(f"• {self.t['last_seen']}: {last_seen}")

            except Exception as e:
                logger.error(f"Error parsing GreyNoise data: {e}")
                lines.append(f"[yellow]Error parsing data[/]")
            
        elif service == 'urlscan':
             try:
                lines.append(f"• {self.t['total_scans']}: {data.get('total', 0)}")
                
                # Get last result info
                results = data.get('results', [])
                if results:
                    last_res = results[0]
                    page = last_res.get('page', {})
                    task = last_res.get('task', {})
                    
                    if 'title' in page: lines.append(f"• {self.t['page_title']}: {page.get('title')}")
                    if 'server' in page: lines.append(f"• {self.t['server']}: {page.get('server')}")
                    if 'country' in page: lines.append(f"• {self.t['country']}: {self._get_country_name(page.get('country'))}")
                    if 'time' in task: 
                         # Format: 2024-01-01T12:00:00.000Z
                         try:
                            dt = datetime.fromisoformat(task.get('time').replace('Z', '+00:00')).strftime('%Y-%m-%d')
                            lines.append(f"• {self.t['last_analysis']}: {dt}")
                         except: pass
                         
             except Exception as e:
                logger.error(f"Error parsing UrlScan data: {e}")
                lines.append(f"[yellow]Error parsing data[/]")

        return "\n".join(lines)

    def print_to_console(self):
        """Prints the report in the requested 'Printable' format."""
        
        # 1. Header
        header_text = f"""
[bold]{self.t['title']}[/]
[dim]{'-'*60}[/]
🎯 {self.t['target']}:    [cyan]{self.target}[/]
🔍 {self.t['type']}:      [cyan]--[/] 
🕒 {self.t['timestamp']}: [dim]{self.timestamp}[/]
[dim]{'-'*60}[/]
        """
        self.console.print(header_text.strip())
        self.console.print()

        # 2. Verdict
        self.console.print(self._get_verdict_panel())
        self.console.print()

        # 3. Services
        for service, data in self.results.items():
            icon_map = {
                'virustotal': '🦠',
                'abuseipdb': '🚫',
                'shodan': '🌐',
                'alienvault': '👽',
                'greynoise': '👻',
                'urlscan': '🔗'
            }
            icon = icon_map.get(service, 'mag')
            title = f"{icon} {service.capitalize()}"
            
            content = self._format_service_content(service, data)
            
            self.console.print(f"[bold]{title}[/]")
            self.console.print(content)
            self.console.print()

        # 4. Footer
        self.console.print(f"[dim]{'-'*60}[/]")
        self.console.print(f"[dim]{self.t['end_report']}[/]")

    def print_dashboard(self):
        """Prints the report in a Dashboard grid layout."""
        self.console.print()
        
        # Header Panel
        header_content = f"[bold cyan]{self.target}[/] [dim]({self.timestamp})[/]"
        header_panel = Panel(Align.center(header_content), title=self.t['title'], border_style="blue")
        
        # Verdict Panel
        verdict_panel = self._get_verdict_panel()
        
        # Service Panels
        panels = []
        for service, data in self.results.items():
            # Hide Forbidden errors (e.g. Quota exceeded) as requested
            if isinstance(data, dict) and data.get("_meta_error") == "forbidden":
                continue
                
            content = self._format_service_content(service, data)
            
            # Risk Color for Border
            border_color = "white"
            if service == 'virustotal':
                if data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0: border_color = "red"
            elif service == 'abuseipdb':
                 if data.get('data', {}).get('abuseConfidenceScore', 0) > 0: border_color = "red"
            
            panels.append(Panel(content, title=f"[bold]{service.upper()}[/]", border_style=border_color))

        # Layout Construction
        self.console.print(header_panel)
        self.console.print(verdict_panel)
        self.console.print(Columns(panels, expand=True))
