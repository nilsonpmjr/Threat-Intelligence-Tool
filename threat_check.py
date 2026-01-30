#!/usr/bin/env python3
import sys
import argparse
import re
import ipaddress
import logging
from api_client import ThreatIntelClient
from report_generator import ReportGenerator

# Configure Logging
logging.basicConfig(level=logging.ERROR, format='%(message)s')
logger = logging.getLogger("ThreatCheck")

def identify_type(target: str) -> str:
    """
    Identifies the type of the target: 'ip', 'domain', 'hash', or 'unknown'.
    """
    target = target.strip()
    
    try:
        ipaddress.ip_address(target)
        return 'ip'
    except ValueError:
        pass
    
    if re.fullmatch(r"^[a-fA-F0-9]{32}$", target): return 'hash'    # MD5
    if re.fullmatch(r"^[a-fA-F0-9]{40}$", target): return 'hash'    # SHA1
    if re.fullmatch(r"^[a-fA-F0-9]{64}$", target): return 'hash'    # SHA256
    
    # Simple check for domain format
    if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", target):
        return 'domain'
        
    return 'unknown'

def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Aggregator")
    parser.add_argument("target", help="IP address, Domain, or File Hash")
    parser.add_argument("--lang", default="pt", help="Language for the report (default: pt)")
    parser.add_argument("--dashboard", action="store_true", help="Show results in a Dashboard view")
    
    args = parser.parse_args()
    target = args.target.strip()
    target_type = identify_type(target)
    
    if target_type == 'unknown':
        print(f"Error: Could not identify the type of target '{target}'.")
        print("Supported types: IPv4/IPv6, Domain, File Hash (MD5/SHA1/SHA256)")
        sys.exit(1)
        
    # Initialize components
    client = ThreatIntelClient()
    report = ReportGenerator(target, lang=args.lang)
    
    from rich.console import Console
    console = Console()
    
    with console.status(f"[bold green]Scanning {target} ({target_type.upper()})...[/]"):
        
        if client.services['virustotal']:
            vt_type = 'file' if target_type == 'hash' else target_type
            result = client.query_virustotal(target, vt_type)
            report.add_result('virustotal', result)
            
        if client.services['alienvault']:
            otx_type = 'file' if target_type == 'hash' else target_type
            result = client.query_alienvault(target, otx_type)
            report.add_result('alienvault', result)
            
        if target_type == 'ip':
            if client.services['abuseipdb']:
                report.add_result('abuseipdb', client.query_abuseipdb(target))
                
            if client.services['shodan']:
                report.add_result('shodan', client.query_shodan(target))
                
            if client.services['greynoise']:
                report.add_result('greynoise', client.query_greynoise(target))
                
        if target_type == 'domain':
            if client.services['urlscan']:
                report.add_result('urlscan', client.query_urlscan(target))
            
    # Output Report
    if args.dashboard:
        report.print_dashboard()
    else:
        report.print_to_console()

if __name__ == "__main__":
    main()
