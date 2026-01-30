# 🛡️ Threat Intelligence Aggregator

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-Passing-success.svg)](tests/)
[![Code Coverage](https://img.shields.io/badge/Coverage-85%25-brightgreen.svg)](coverage/)

Uma ferramenta poderosa e eficiente para agregar inteligência de ameaças de múltiplas fontes, incluindo VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, GreyNoise e URLScan.

## ✨ Características

- 🚀 **Consultas Paralelas Assíncronas** - Resultados rápidos com asyncio
- 💾 **Sistema de Cache Inteligente** - Cache com TTL para evitar requisições desnecessárias
- ⚡ **Rate Limiting Automático** - Respeita limites de API automaticamente
- 🔄 **Retry com Backoff Exponencial** - Recuperação automática de falhas temporárias
- 🎨 **Interface Rica** - Visualização elegante com Rich library
- 🌍 **Suporte Multi-idioma** - Português e Inglês
- 🔒 **Validação Robusta** - Proteção contra inputs maliciosos
- 📊 **Múltiplos Formatos de Saída** - Console, Dashboard, JSON, CSV, HTML
- 🧪 **Totalmente Testado** - Cobertura de testes > 80%

## 📋 Requisitos

- Python 3.9 ou superior
- Chaves API para os serviços desejados (veja [Configuração](#-configuração))

## 🚀 Instalação

### Instalação Básica

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/threat-tool.git
cd threat-tool

# Crie um ambiente virtual (recomendado)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Instale as dependências
pip install -r requirements.txt
```

### Instalação para Desenvolvimento

```bash
# Instale dependências de desenvolvimento
pip install -r requirements-dev.txt

# Instale pre-commit hooks
pre-commit install

# Execute os testes
pytest
```

### Instalação via pip (futuro)

```bash
pip install threat-tool
```

## ⚙️ Configuração

### 1. Obtenha Chaves API

Você precisará de chaves API dos serviços que deseja utilizar:

| Serviço | URL de Registro | Tipo | Suporte |
|---------|----------------|------|---------|
| [VirusTotal](https://www.virustotal.com/gui/join-us) | virustotal.com | IP, Domain, Hash | ✅ |
| [AbuseIPDB](https://www.abuseipdb.com/register) | abuseipdb.com | IP | ✅ |
| [Shodan](https://account.shodan.io/register) | shodan.io | IP | ✅ |
| [AlienVault OTX](https://otx.alienvault.com/accounts/signup/) | otx.alienvault.com | IP, Domain, Hash | ✅ |
| [GreyNoise](https://viz.greynoise.io/signup) | greynoise.io | IP | ✅ |
| [URLScan](https://urlscan.io/user/signup) | urlscan.io | Domain | ✅ |

> **Nota**: Todos os serviços oferecem um plano gratuito. A ferramenta funciona mesmo se você tiver apenas algumas chaves configuradas.

### 2. Configure as Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto:

```bash
# Copie o template
cp .env.example .env

# Edite com suas chaves API
nano .env
```

Conteúdo do `.env`:

```bash
# VirusTotal
VT_API_KEY=sua_chave_virustotal_aqui

# AbuseIPDB
ABUSEIPDB_API_KEY=sua_chave_abuseipdb_aqui

# Shodan
SHODAN_API_KEY=sua_chave_shodan_aqui

# AlienVault OTX
OTX_API_KEY=sua_chave_otx_aqui

# GreyNoise
GREYNOISE_API_KEY=sua_chave_greynoise_aqui

# URLScan
URLSCAN_API_KEY=sua_chave_urlscan_aqui
```

### 3. Configuração Alternativa (Linux/Mac)

Você também pode exportar as variáveis diretamente:

```bash
export VT_API_KEY="sua_chave_aqui"
export ABUSEIPDB_API_KEY="sua_chave_aqui"
# ... outras chaves
```

## 📖 Uso

### Uso Básico

```bash
# Analisar um IP
python threat_check.py 8.8.8.8

# Analisar um domínio
python threat_check.py example.com

# Analisar um hash de arquivo
python threat_check.py 5d41402abc4b2a76b9719d911017c592
```

### Opções Avançadas

```bash
# Especificar idioma (pt ou en)
python threat_check.py 8.8.8.8 --lang pt

# Modo Dashboard (visualização em grid)
python threat_check.py 8.8.8.8 --dashboard

# Combinar opções
python threat_check.py malware.exe --lang en --dashboard
```

### Uso via Módulo Python

```python
import asyncio
from threat_tool import AsyncThreatIntelClient
from threat_tool.validators import validate_target

async def main():
    # Validar entrada
    target = validate_target("8.8.8.8")
    
    # Consultar APIs
    async with AsyncThreatIntelClient() as client:
        results = await client.query_all(
            target.sanitized,
            target.target_type
        )
        
        # Processar resultados
        for service, response in results.items():
            if response.success:
                print(f"{service}: {response.data}")
            else:
                print(f"{service}: Error - {response.error}")

asyncio.run(main())
```

## 📊 Exemplos de Saída

### Modo Console (Padrão)

```
RELATÓRIO DE INTELIGÊNCIA DE AMEAÇAS
────────────────────────────────────────────────────────
🎯 Alvo:    8.8.8.8
🔍 Tipo:    IP
🕒 Data/Hora: 2026-01-29 20:30:45 BRT
────────────────────────────────────────────────────────

╭─────────────────────────────────────────────────────────╮
│              🛡️  VEREDITO: SEGURO (0/6)                │
╰─────────────────────────────────────────────────────────╯

🦠 Virustotal
• Pontuação: 0/93 Fornecedores
• Votos da Comunidade: 👍 1234 / 👎 5
• Última Análise: 2026-01-28
• País: United States
• Organização: Google LLC

🚫 Abuseipdb
• Confiança: 0%
• Denúncias: 0
• Tipo de Uso: Content Delivery Network
• País: United States
• ISP: Google LLC

────────────────────────────────────────────────────────
Fim do Relatório
```

### Modo Dashboard

```
╭──────────────────── THREAT INTELLIGENCE REPORT ────────────────────╮
│                    8.8.8.8 (2026-01-29 20:30:45)                   │
╰────────────────────────────────────────────────────────────────────╯

╭───────────────────────────╮
│   🛡️  VEREDITO: SEGURO   │
│        (0/6 Fontes)       │
╰───────────────────────────╯

┌─────────────────┬─────────────────┬─────────────────┐
│  VIRUSTOTAL     │   ABUSEIPDB     │    SHODAN       │
├─────────────────┼─────────────────┼─────────────────┤
│ Score: 0/93     │ Confidence: 0%  │ OS: Linux       │
│ Safe            │ Reports: 0      │ Ports: 53, 443  │
└─────────────────┴─────────────────┴─────────────────┘
```

## 🧪 Testes

Execute a suite completa de testes:

```bash
# Executar todos os testes
pytest

# Executar com cobertura
pytest --cov=threat_tool --cov-report=html

# Executar apenas testes de segurança
pytest tests/test_security.py -v

# Executar testes específicos
pytest tests/test_validators.py::TestInputValidator::test_validate_ipv4_valid -v
```

## 🔒 Segurança

### Práticas Implementadas

- ✅ Validação rigorosa de todos os inputs
- ✅ Sanitização de dados antes de processamento
- ✅ Proteção contra SQL injection, XSS, command injection
- ✅ Rate limiting para evitar abuso
- ✅ Logs sanitizados (sem exposição de chaves API)
- ✅ Timeout em todas as requisições
- ✅ Retry com limite para evitar loops infinitos

### Reporte de Vulnerabilidades

Se você descobrir uma vulnerabilidade de segurança, por favor **NÃO** abra uma issue pública. 

Envie um email para: security@example.com

## 🛣️ Roadmap

### v2.0 (Atual)
- [x] Consultas assíncronas paralelas
- [x] Sistema de cache com TTL
- [x] Rate limiting automático
- [x] Validação robusta de inputs
- [x] Testes automatizados
- [x] Multi-idioma (PT/EN)

### v2.1 (Planejado)
- [ ] Exportação para JSON, CSV, HTML, PDF
- [ ] API REST (FastAPI)
- [ ] Dashboard Web interativo
- [ ] Suporte a mais fontes de threat intel
- [ ] Sistema de plugins
- [ ] Banco de dados para histórico

### v3.0 (Futuro)
- [ ] Machine Learning para análise preditiva
- [ ] Integração com SIEM
- [ ] Modo colaborativo multi-usuário
- [ ] Mobile app (iOS/Android)

## 🤝 Contribuindo

Contribuições são bem-vindas! Por favor, leia nosso [Guia de Contribuição](CONTRIBUTING.md) antes de submeter PRs.

### Como Contribuir

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

### Código de Conduta

Este projeto adere ao [Código de Conduta do Contributor Covenant](CODE_OF_CONDUCT.md).

## 📝 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 👥 Autores

- **Seu Nome** - *Trabalho Inicial* - [@seu-github](https://github.com/seu-usuario)

Veja também a lista de [contribuidores](https://github.com/seu-usuario/threat-tool/contributors).

## 🙏 Agradecimentos

- [VirusTotal](https://www.virustotal.com) - API de análise de malware
- [AbuseIPDB](https://www.abuseipdb.com) - Reputação de IPs
- [Shodan](https://www.shodan.io) - Busca de dispositivos IoT
- [AlienVault OTX](https://otx.alienvault.com) - Threat intelligence colaborativa
- [GreyNoise](https://www.greynoise.io) - Internet background noise
- [URLScan](https://urlscan.io) - Análise de URLs
- [Rich](https://github.com/Textualize/rich) - Terminal formatting

## 📧 Contato

- Email: seu-email@example.com
- Twitter: [@seu-twitter](https://twitter.com/seu-twitter)
- LinkedIn: [Seu Nome](https://linkedin.com/in/seu-perfil)

## 💖 Apoie o Projeto

Se este projeto foi útil para você, considere:

- ⭐ Dar uma estrela no GitHub
- 🐦 Compartilhar no Twitter
- ☕ [Comprar um café](https://buymeacoffee.com/seu-usuario)

---

<p align="center">
  Feito com ❤️ e ☕
</p>
