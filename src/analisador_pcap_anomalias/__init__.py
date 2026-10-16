"""Analisador de tráfego PCAP com detecção de anomalias de volume e protocolo."""

from .analisador import (
    EstatisticaProtocolo,
    Pacote,
    estatisticas_dataframe,
    ler_pcap,
)
from .detector import (
    Anomalia,
    detectar_anomalias,
    detectar_protocolo,
    detectar_volume,
)
from .relatorio import gerar_relatorio, salvar_relatorio

__all__ = [
    "Pacote",
    "EstatisticaProtocolo",
    "Anomalia",
    "ler_pcap",
    "estatisticas_dataframe",
    "detectar_anomalias",
    "detectar_volume",
    "detectar_protocolo",
    "gerar_relatorio",
    "salvar_relatorio",
]

__version__ = "0.1.0"
