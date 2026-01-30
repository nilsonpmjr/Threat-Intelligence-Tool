"""
Módulo de validação de inputs para Threat Intelligence Tool.

Este módulo fornece validação robusta e segura de diferentes tipos de indicadores
de ameaça (IoCs - Indicators of Compromise).
"""

import re
import ipaddress
from typing import Tuple
from dataclasses import dataclass


class ValidationError(Exception):
    """Exceção levantada quando a validação de input falha."""
    pass


@dataclass
class ValidatedTarget:
    """Representa um alvo validado e sanitizado."""
    original: str
    sanitized: str
    target_type: str
    
    def __str__(self) -> str:
        return f"{self.sanitized} ({self.target_type})"


class InputValidator:
    """
    Valida e identifica tipos de indicadores de ameaça.
    
    Suporta:
    - Endereços IPv4 e IPv6
    - Nomes de domínio
    - Hashes de arquivo (MD5, SHA1, SHA256)
    """
    
    # Constantes de configuração
    MAX_INPUT_LENGTH = 256
    MAX_DOMAIN_LENGTH = 253  # RFC 1035
    
    # Padrões de regex compilados para performance
    HASH_PATTERNS = {
        'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
        'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
        'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
    }
    
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    # Whitelist de caracteres permitidos (segurança)
    ALLOWED_CHARS_PATTERN = re.compile(r'^[a-fA-F0-9.:/-]+$')
    
    @classmethod
    def validate(cls, target: str) -> ValidatedTarget:
        """
        Valida e identifica o tipo de um alvo.
        
        Args:
            target: String contendo o indicador a ser validado
            
        Returns:
            ValidatedTarget com dados sanitizados e tipo identificado
            
        Raises:
            ValidationError: Se o input for inválido
            
        Examples:
            >>> validator = InputValidator()
            >>> result = validator.validate("8.8.8.8")
            >>> print(result.target_type)
            'ip'
            
            >>> result = validator.validate("example.com")
            >>> print(result.target_type)
            'domain'
        """
        # Validação básica
        if not target or not isinstance(target, str):
            raise ValidationError("Target must be a non-empty string")
        
        original = target
        target = target.strip()
        
        # Validação de tamanho
        if len(target) > cls.MAX_INPUT_LENGTH:
            raise ValidationError(
                f"Target exceeds maximum length of {cls.MAX_INPUT_LENGTH} characters"
            )
        
        # Validação de tamanho mínimo
        if len(target) < 3:
            raise ValidationError("Target is too short (minimum 3 characters)")
        
        # Tenta identificar o tipo
        target_type = cls._identify_type(target)
        
        if target_type == 'unknown':
            raise ValidationError(
                f"Could not identify target type. "
                f"Supported types: IPv4/IPv6, Domain, Hash (MD5/SHA1/SHA256)"
            )
        
        # Sanitização baseada no tipo
        sanitized = cls._sanitize(target, target_type)
        
        return ValidatedTarget(
            original=original,
            sanitized=sanitized,
            target_type=target_type
        )
    
    @classmethod
    def _identify_type(cls, target: str) -> str:
        """
        Identifica o tipo do alvo.
        
        Args:
            target: String a ser identificada
            
        Returns:
            Tipo identificado: 'ip', 'domain', 'hash', ou 'unknown'
        """
        # Tenta identificar como IP (IPv4 ou IPv6)
        if cls._is_valid_ip(target):
            return 'ip'
        
        # Tenta identificar como hash
        if cls._is_valid_hash(target):
            return 'hash'
        
        # Tenta identificar como domínio
        if cls._is_valid_domain(target):
            return 'domain'
        
        return 'unknown'
    
    @classmethod
    def _is_valid_ip(cls, target: str) -> bool:
        """Verifica se é um endereço IP válido."""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    @classmethod
    def _is_valid_hash(cls, target: str) -> bool:
        """Verifica se é um hash válido (MD5, SHA1, ou SHA256)."""
        for hash_type, pattern in cls.HASH_PATTERNS.items():
            if pattern.fullmatch(target):
                return True
        return False
    
    @classmethod
    def _is_valid_domain(cls, target: str) -> bool:
        """
        Verifica se é um domínio válido.
        
        Validações:
        - Formato correto (RFC 1035)
        - Tamanho dentro dos limites
        - Sem caracteres especiais perigosos
        """
        if len(target) > cls.MAX_DOMAIN_LENGTH:
            return False
        
        if not cls.DOMAIN_PATTERN.fullmatch(target):
            return False
        
        # Verificações adicionais
        labels = target.split('.')
        
        # Cada label deve ter no máximo 63 caracteres
        if any(len(label) > 63 for label in labels):
            return False
        
        # Não pode começar ou terminar com hífen
        if any(label.startswith('-') or label.endswith('-') for label in labels):
            return False
        
        return True
    
    @classmethod
    def _sanitize(cls, target: str, target_type: str) -> str:
        """
        Sanitiza o alvo baseado no seu tipo.
        
        Args:
            target: Alvo a ser sanitizado
            target_type: Tipo do alvo
            
        Returns:
            Alvo sanitizado
        """
        if target_type == 'ip':
            # Normaliza o IP (remove zeros à esquerda, etc.)
            return str(ipaddress.ip_address(target))
        
        elif target_type == 'hash':
            # Hashes sempre em minúsculo
            return target.lower()
        
        elif target_type == 'domain':
            # Domínios sempre em minúsculo, sem trailing dot
            return target.lower().rstrip('.')
        
        return target


class TargetTypeIdentifier:
    """
    Identificador rápido de tipo de alvo sem validação completa.
    
    Use quando a performance for mais importante que a validação rigorosa.
    """
    
    @staticmethod
    def quick_identify(target: str) -> str:
        """
        Identificação rápida sem validação rigorosa.
        
        Args:
            target: String a ser identificada
            
        Returns:
            Tipo identificado: 'ip', 'domain', 'hash', ou 'unknown'
        """
        target = target.strip()
        
        # IP
        try:
            ipaddress.ip_address(target)
            return 'ip'
        except ValueError:
            pass
        
        # Hash (apenas verifica tamanho)
        if len(target) in (32, 40, 64) and target.isalnum():
            return 'hash'
        
        # Domain (check simples)
        if '.' in target and not target.replace('.', '').replace('-', '').isalnum():
            return 'unknown'
        
        if '.' in target:
            return 'domain'
        
        return 'unknown'


# Funções de conveniência
def validate_target(target: str) -> ValidatedTarget:
    """
    Função de conveniência para validar um alvo.
    
    Args:
        target: Alvo a ser validado
        
    Returns:
        ValidatedTarget
        
    Raises:
        ValidationError: Se o alvo for inválido
    """
    return InputValidator.validate(target)


def identify_type(target: str) -> str:
    """
    Função de conveniência para identificar o tipo de um alvo.
    
    Args:
        target: Alvo a ser identificado
        
    Returns:
        Tipo: 'ip', 'domain', 'hash', ou 'unknown'
    """
    try:
        result = InputValidator.validate(target)
        return result.target_type
    except ValidationError:
        return 'unknown'
