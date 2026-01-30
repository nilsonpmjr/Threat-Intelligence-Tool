"""
Configuração centralizada de logging.
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler


def setup_logging(
    level: str = "INFO",
    log_file: Path = None,
    console: bool = True
):
    """
    Configura o sistema de logging.
    
    Args:
        level: Nível de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Caminho para arquivo de log (opcional)
        console: Se True, também loga no console
    """
    # Configuração do formato
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Criar formatter
    formatter = logging.Formatter(log_format, date_format)
    
    # Logger raiz
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Remover handlers existentes
    root_logger.handlers = []
    
    # Console handler
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    # File handler (se especificado)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Suprimir logs verbose de bibliotecas
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    
    logger = logging.getLogger(__name__)
    logger.debug(f"Logging initialized at {level} level")


def get_logger(name: str) -> logging.Logger:
    """
    Retorna um logger configurado.
    
    Args:
        name: Nome do módulo (geralmente __name__)
        
    Returns:
        Logger configurado
    """
    return logging.getLogger(name)
