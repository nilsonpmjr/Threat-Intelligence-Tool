"""
Cliente API melhorado para Threat Intelligence Tool.

Features:
- Suporte async/await para consultas paralelas
- Cache com TTL
- Rate limiting
- Retry com backoff exponencial
- Logging estruturado
- Tratamento robusto de erros
"""

import os
import asyncio
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict
import aiohttp
from cachetools import TTLCache


# Configuração de logging
logger = logging.getLogger(__name__)


class APIError(Exception):
    """Exceção base para erros de API."""
    pass


class RateLimitError(APIError):
    """Exceção levantada quando rate limit é excedido."""
    pass


class AuthenticationError(APIError):
    """Exceção levantada quando autenticação falha."""
    pass


@dataclass
class APIResponse:
    """Representa uma resposta de API."""
    service: str
    data: Optional[Dict[str, Any]]
    success: bool
    error: Optional[str] = None
    cached: bool = False
    
    def is_error(self) -> bool:
        """Retorna True se a resposta é um erro."""
        return not self.success or self.error is not None


class RateLimiter:
    """
    Implementa rate limiting por serviço.
    
    Usa algoritmo de sliding window para limitar requisições.
    """
    
    def __init__(self, calls: int = 4, period: int = 60):
        """
        Args:
            calls: Número máximo de chamadas permitidas
            period: Período em segundos
        """
        self.calls = calls
        self.period = period
        self.requests = defaultdict(list)
    
    async def acquire(self, key: str) -> bool:
        """
        Tenta adquirir permissão para fazer uma requisição.
        
        Args:
            key: Chave identificadora (normalmente o serviço)
            
        Returns:
            True se permitido, False caso contrário
        """
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.period)
        
        # Remove requisições antigas
        self.requests[key] = [
            req_time for req_time in self.requests[key]
            if req_time > cutoff
        ]
        
        if len(self.requests[key]) < self.calls:
            self.requests[key].append(now)
            return True
        
        return False
    
    async def wait_if_needed(self, key: str, max_wait: int = 60) -> None:
        """
        Aguarda se necessário até que rate limit permita.
        
        Args:
            key: Chave identificadora
            max_wait: Tempo máximo de espera em segundos
            
        Raises:
            RateLimitError: Se tempo de espera exceder max_wait
        """
        start_time = datetime.now()
        
        while not await self.acquire(key):
            elapsed = (datetime.now() - start_time).total_seconds()
            
            if elapsed > max_wait:
                raise RateLimitError(f"Rate limit exceeded for {key}")
            
            await asyncio.sleep(1)


class AsyncThreatIntelClient:
    """
    Cliente assíncrono para consultas de Threat Intelligence.
    
    Suporta múltiplas APIs com cache, rate limiting e retry logic.
    
    Example:
        >>> async with AsyncThreatIntelClient() as client:
        ...     results = await client.query_all("8.8.8.8", "ip")
        ...     for service, response in results.items():
        ...         print(f"{service}: {response.success}")
    """
    
    # Configuração de serviços
    SERVICES_CONFIG = {
        'virustotal': {
            'env_var': 'VT_API_KEY',
            'base_url': 'https://www.virustotal.com/api/v3',
            'rate_limit': (4, 60),  # 4 calls per minute
        },
        'abuseipdb': {
            'env_var': 'ABUSEIPDB_API_KEY',
            'base_url': 'https://api.abuseipdb.com/api/v2',
            'rate_limit': (10, 60),
        },
        'shodan': {
            'env_var': 'SHODAN_API_KEY',
            'base_url': 'https://api.shodan.io',
            'rate_limit': (1, 1),  # 1 call per second for free tier
        },
        'alienvault': {
            'env_var': 'OTX_API_KEY',
            'base_url': 'https://otx.alienvault.com/api/v1',
            'rate_limit': (10, 60),
        },
        'greynoise': {
            'env_var': 'GREYNOISE_API_KEY',
            'base_url': 'https://api.greynoise.io/v3',
            'rate_limit': (10, 60),
        },
        'urlscan': {
            'env_var': 'URLSCAN_API_KEY',
            'base_url': 'https://urlscan.io/api/v1',
            'rate_limit': (10, 60),
        },
    }
    
    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 3,
        cache_ttl: int = 3600,  # 1 hora
        cache_size: int = 100
    ):
        """
        Args:
            timeout: Timeout para requisições em segundos
            max_retries: Número máximo de tentativas
            cache_ttl: TTL do cache em segundos
            cache_size: Tamanho máximo do cache
        """
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Cache
        self.cache = TTLCache(maxsize=cache_size, ttl=cache_ttl)
        
        # Rate limiters por serviço
        self.rate_limiters = {
            service: RateLimiter(*config['rate_limit'])
            for service, config in self.SERVICES_CONFIG.items()
        }
        
        # Carregar chaves API
        self.api_keys = self._load_api_keys()
        self.services = {
            service: bool(self.api_keys.get(service))
            for service in self.SERVICES_CONFIG.keys()
        }
        
        logger.info(f"Initialized client with {sum(self.services.values())} active services")
    
    def _load_api_keys(self) -> Dict[str, str]:
        """Carrega chaves API das variáveis de ambiente."""
        keys = {}
        
        for service, config in self.SERVICES_CONFIG.items():
            key = os.getenv(config['env_var'])
            if key:
                keys[service] = key
                logger.debug(f"{service} API key loaded")
            else:
                logger.warning(f"{service} disabled - missing {config['env_var']}")
        
        return keys
    
    async def __aenter__(self):
        """Context manager entry."""
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self.session:
            await self.session.close()
    
    def _get_cache_key(self, service: str, target: str, endpoint: str = "") -> str:
        """Gera chave de cache."""
        return f"{service}:{target}:{endpoint}"
    
    async def _safe_request(
        self,
        service: str,
        method: str,
        url: str,
        **kwargs
    ) -> APIResponse:
        """
        Faz requisição com retry, rate limiting e cache.
        
        Args:
            service: Nome do serviço
            method: Método HTTP
            url: URL da requisição
            **kwargs: Argumentos adicionais para aiohttp
            
        Returns:
            APIResponse com resultado
        """
        # Verificar rate limit
        await self.rate_limiters[service].wait_if_needed(service)
        
        # Tentar com retry
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                async with self.session.request(method, url, **kwargs) as response:
                    # Tratamento de status codes
                    if response.status == 404:
                        return APIResponse(
                            service=service,
                            data=None,
                            success=False,
                            error="Not found in database"
                        )
                    
                    if response.status == 403:
                        return APIResponse(
                            service=service,
                            data=None,
                            success=False,
                            error="Access denied - Check quota/API key"
                        )
                    
                    if response.status == 401:
                        raise AuthenticationError("Invalid API key")
                    
                    if response.status == 429:
                        wait_time = min(2 ** attempt, 32)  # Exponential backoff
                        logger.warning(f"Rate limited, waiting {wait_time}s")
                        await asyncio.sleep(wait_time)
                        continue
                    
                    response.raise_for_status()
                    data = await response.json()
                    
                    return APIResponse(
                        service=service,
                        data=data,
                        success=True
                    )
                    
            except asyncio.TimeoutError:
                last_error = "Request timeout"
                logger.warning(f"Timeout on attempt {attempt + 1}/{self.max_retries}")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                
            except aiohttp.ClientError as e:
                last_error = str(e)
                logger.error(f"Client error on attempt {attempt + 1}: {e}")
                await asyncio.sleep(2 ** attempt)
                
            except Exception as e:
                last_error = str(e)
                logger.error(f"Unexpected error: {e}")
                break
        
        return APIResponse(
            service=service,
            data=None,
            success=False,
            error=last_error or "Unknown error"
        )
    
    async def query_virustotal(self, target: str, type_hint: str) -> APIResponse:
        """
        Consulta VirusTotal API.
        
        Args:
            target: IP, Domain, ou Hash
            type_hint: 'ip', 'domain', ou 'file'
            
        Returns:
            APIResponse com resultado
        """
        if not self.services.get('virustotal'):
            return APIResponse(
                service='virustotal',
                data=None,
                success=False,
                error="Service not available"
            )
        
        # Verificar cache
        cache_key = self._get_cache_key('virustotal', target, type_hint)
        if cache_key in self.cache:
            logger.debug(f"Cache hit for {cache_key}")
            return APIResponse(
                service='virustotal',
                data=self.cache[cache_key],
                success=True,
                cached=True
            )
        
        endpoint_map = {
            'ip': 'ip_addresses',
            'domain': 'domains',
            'file': 'files'
        }
        
        endpoint = endpoint_map.get(type_hint)
        if not endpoint:
            return APIResponse(
                service='virustotal',
                data=None,
                success=False,
                error=f"Invalid type_hint: {type_hint}"
            )
        
        url = f"{self.SERVICES_CONFIG['virustotal']['base_url']}/{endpoint}/{target}"
        headers = {"x-apikey": self.api_keys['virustotal']}
        
        response = await self._safe_request('virustotal', 'GET', url, headers=headers)
        
        # Adicionar ao cache se sucesso
        if response.success and response.data:
            self.cache[cache_key] = response.data
        
        return response
    
    async def query_abuseipdb(self, ip: str) -> APIResponse:
        """Consulta AbuseIPDB API."""
        if not self.services.get('abuseipdb'):
            return APIResponse(
                service='abuseipdb',
                data=None,
                success=False,
                error="Service not available"
            )
        
        cache_key = self._get_cache_key('abuseipdb', ip)
        if cache_key in self.cache:
            return APIResponse(
                service='abuseipdb',
                data=self.cache[cache_key],
                success=True,
                cached=True
            )
        
        url = f"{self.SERVICES_CONFIG['abuseipdb']['base_url']}/check"
        headers = {
            'Key': self.api_keys['abuseipdb'],
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        
        response = await self._safe_request(
            'abuseipdb', 'GET', url,
            headers=headers, params=params
        )
        
        if response.success and response.data:
            self.cache[cache_key] = response.data
        
        return response
    
    async def query_shodan(self, ip: str) -> APIResponse:
        """Consulta Shodan API."""
        if not self.services.get('shodan'):
            return APIResponse(
                service='shodan',
                data=None,
                success=False,
                error="Service not available"
            )
        
        cache_key = self._get_cache_key('shodan', ip)
        if cache_key in self.cache:
            return APIResponse(
                service='shodan',
                data=self.cache[cache_key],
                success=True,
                cached=True
            )
        
        url = f"{self.SERVICES_CONFIG['shodan']['base_url']}/shodan/host/{ip}"
        params = {'key': self.api_keys['shodan']}
        
        response = await self._safe_request('shodan', 'GET', url, params=params)
        
        if response.success and response.data:
            self.cache[cache_key] = response.data
        
        return response
    
    async def query_alienvault(self, target: str, type_hint: str) -> APIResponse:
        """Consulta AlienVault OTX API."""
        if not self.services.get('alienvault'):
            return APIResponse(
                service='alienvault',
                data=None,
                success=False,
                error="Service not available"
            )
        
        # Map type hints
        otx_type = 'IPv4' if type_hint == 'ip' else type_hint
        
        if otx_type not in ['IPv4', 'domain', 'file']:
            return APIResponse(
                service='alienvault',
                data=None,
                success=False,
                error=f"Invalid type_hint: {type_hint}"
            )
        
        cache_key = self._get_cache_key('alienvault', target, otx_type)
        if cache_key in self.cache:
            return APIResponse(
                service='alienvault',
                data=self.cache[cache_key],
                success=True,
                cached=True
            )
        
        url = f"{self.SERVICES_CONFIG['alienvault']['base_url']}/indicators/{otx_type}/{target}/general"
        headers = {"X-OTX-API-KEY": self.api_keys['alienvault']}
        
        response = await self._safe_request('alienvault', 'GET', url, headers=headers)
        
        if response.success and response.data:
            self.cache[cache_key] = response.data
        
        return response
    
    async def query_greynoise(self, ip: str) -> APIResponse:
        """Consulta GreyNoise Community API."""
        if not self.services.get('greynoise'):
            return APIResponse(
                service='greynoise',
                data=None,
                success=False,
                error="Service not available"
            )
        
        cache_key = self._get_cache_key('greynoise', ip)
        if cache_key in self.cache:
            return APIResponse(
                service='greynoise',
                data=self.cache[cache_key],
                success=True,
                cached=True
            )
        
        url = f"{self.SERVICES_CONFIG['greynoise']['base_url']}/community/{ip}"
        headers = {"key": self.api_keys['greynoise']}
        
        response = await self._safe_request('greynoise', 'GET', url, headers=headers)
        
        if response.success and response.data:
            self.cache[cache_key] = response.data
        
        return response
    
    async def query_urlscan(self, domain: str) -> APIResponse:
        """Consulta URLScan.io API."""
        if not self.services.get('urlscan'):
            return APIResponse(
                service='urlscan',
                data=None,
                success=False,
                error="Service not available"
            )
        
        cache_key = self._get_cache_key('urlscan', domain)
        if cache_key in self.cache:
            return APIResponse(
                service='urlscan',
                data=self.cache[cache_key],
                success=True,
                cached=True
            )
        
        url = f"{self.SERVICES_CONFIG['urlscan']['base_url']}/search/"
        headers = {"API-Key": self.api_keys['urlscan']}
        params = {"q": f"domain:{domain}"}
        
        response = await self._safe_request(
            'urlscan', 'GET', url,
            headers=headers, params=params
        )
        
        if response.success and response.data:
            self.cache[cache_key] = response.data
        
        return response
    
    async def query_all(self, target: str, target_type: str) -> Dict[str, APIResponse]:
        """
        Consulta todas as APIs disponíveis em paralelo.
        
        Args:
            target: Alvo da consulta
            target_type: Tipo do alvo ('ip', 'domain', 'hash')
            
        Returns:
            Dicionário com respostas de cada serviço
        """
        tasks = []
        
        # VirusTotal e AlienVault suportam todos os tipos
        if self.services['virustotal']:
            vt_type = 'file' if target_type == 'hash' else target_type
            tasks.append(('virustotal', self.query_virustotal(target, vt_type)))
        
        if self.services['alienvault']:
            otx_type = 'file' if target_type == 'hash' else target_type
            tasks.append(('alienvault', self.query_alienvault(target, otx_type)))
        
        # Serviços específicos para IP
        if target_type == 'ip':
            if self.services['abuseipdb']:
                tasks.append(('abuseipdb', self.query_abuseipdb(target)))
            
            if self.services['shodan']:
                tasks.append(('shodan', self.query_shodan(target)))
            
            if self.services['greynoise']:
                tasks.append(('greynoise', self.query_greynoise(target)))
        
        # URLScan para domínios
        if target_type == 'domain' and self.services['urlscan']:
            tasks.append(('urlscan', self.query_urlscan(target)))
        
        # Executar todas as consultas em paralelo
        results = {}
        if tasks:
            responses = await asyncio.gather(*[task for _, task in tasks])
            results = {service: response for (service, _), response in zip(tasks, responses)}
        
        return results
