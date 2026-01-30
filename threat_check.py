#!/usr/bin/env python3
import sys
import argparse
import logging
from rich.console import Console
from api_client import ThreatIntelClient
from report_generator import ReportGenerator
from logging_config import setup_logging, get_logger
from validators import validate_target, ValidationError

logger = get_logger("ThreatCheck")

def main():
    setup_logging(level="INFO")
    
    parser = argparse.ArgumentParser(description="Threat Intelligence Aggregator")
    parser.add_argument("target", help="IP address, Domain, or File Hash")
    parser.add_argument("--lang", default="pt", help="Language for the report (default: pt)")
    parser.add_argument("--dashboard", action="store_true", help="Show results in a Dashboard view")
    
    args = parser.parse_args()
    
    try:
        validated = validate_target(args.target)
        target = validated.sanitized
        target_type = validated.target_type
        
        logger.info(f"Target validated: {target} ({target_type})")
        
    except ValidationError as e:
        console = Console()
        console.print(f"[red]❌ Validation Error:[/] {e}")
        console.print("\n[yellow]Supported types:[/]")
        console.print("  • IPv4/IPv6 addresses")
        console.print("  • Domain names")
        console.print("  • File hashes (MD5, SHA1, SHA256)")
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
