"""Leitura de arquivos PCAP e estatísticas de tráfego."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from scapy.all import IP, rdpcap

# Número do protocolo IP -> nome legível.
PROTOCOLOS: dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}


@dataclass(frozen=True)
class Pacote:
    """Um pacote IP extraído de um arquivo PCAP."""

    timestamp: float
    origem: str
    destino: str
    protocolo: str
    tamanho: int


@dataclass(frozen=True)
class EstatisticaProtocolo:
    """Agregação de tráfego de um protocolo."""

    protocolo: str
    pacotes: int
    bytes: int


def ler_pcap(caminho: str | Path) -> list[Pacote]:
    """Lê um arquivo PCAP e devolve os pacotes IP contidos nele.

    Pacotes sem camada IP (ARP, por exemplo) são ignorados.
    Levanta FileNotFoundError quando o caminho não existe.
    """
    caminho = Path(caminho)
    if not caminho.exists():
        raise FileNotFoundError(f"Arquivo PCAP não encontrado: {caminho}")
    pacotes_raw = rdpcap(str(caminho))
    resultado: list[Pacote] = []
    for pkt in pacotes_raw:
        if not pkt.haslayer(IP):
            continue
        ip = pkt[IP]
        nome = PROTOCOLOS.get(int(ip.proto), "OUTRO")
        resultado.append(
            Pacote(
                timestamp=float(pkt.time),
                origem=str(ip.src),
                destino=str(ip.dst),
                protocolo=nome,
                tamanho=int(len(pkt)),
            )
        )
    return resultado


def estatisticas_dataframe(pacotes: list[Pacote]) -> pd.DataFrame:
    """Devolve DataFrame com total de pacotes e bytes por protocolo.

    As linhas vêm ordenadas por nome de protocolo, o que deixa o resultado
    determinístico independente da ordem dos pacotes no PCAP.
    """
    agregado: dict[str, dict[str, int]] = {}
    for pkt in pacotes:
        entrada = agregado.setdefault(pkt.protocolo, {"pacotes": 0, "bytes": 0})
        entrada["pacotes"] += 1
        entrada["bytes"] += pkt.tamanho
    linhas = [
        {"protocolo": nome, "pacotes": dados["pacotes"], "bytes": dados["bytes"]}
        for nome, dados in sorted(agregado.items())
    ]
    return pd.DataFrame(linhas, columns=["protocolo", "pacotes", "bytes"])
