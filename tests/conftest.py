"""Fixtures e utilitários compartilhados para os testes do analisador de PCAP."""

from __future__ import annotations

from pathlib import Path

import pytest
from scapy.all import ARP, Ether, ICMP, IP, TCP, UDP, wrpcap

# Número do protocolo IP -> nome legível.
PROTO_NUM_TO_NOME = {1: "ICMP", 6: "TCP", 17: "UDP"}


def fabricar_pacote(
    timestamp: float,
    origem: str,
    destino: str,
    proto_num: int,
    tamanho_total: int,
) -> object:
    """Constrói um pacote Ethernet/IP com camada de transporte e tamanho alvo.

    Útil para gerar PCAPs sintéticos e determinísticos nos testes.
    """
    ip = IP(src=origem, dst=destino, proto=proto_num)
    camada_transporte = {
        6: TCP(sport=4000, dport=80),
        17: UDP(sport=4000, dport=53),
        1: ICMP(),
    }.get(proto_num)
    pacote = Ether() / ip
    if camada_transporte is not None:
        pacote = pacote / camada_transporte
    preenchimento = max(0, tamanho_total - len(pacote))
    if preenchimento:
        pacote = pacote / (b"\x00" * preenchimento)
    pacote.time = timestamp
    return pacote


@pytest.fixture
def pcap_baixo_traffico(tmp_path: Path) -> Path:
    """PCAP com poucos pacotes, abaixo de qualquer limiar de anomalia."""
    caminho = tmp_path / "baixo_traffico.pcap"
    pacotes = [
        fabricar_pacote(0.0, "10.0.0.1", "10.0.0.2", 6, 80),
        fabricar_pacote(0.5, "10.0.0.2", "10.0.0.1", 17, 80),
        fabricar_pacote(1.0, "10.0.0.1", "10.0.0.3", 1, 80),
    ]
    wrpcap(str(caminho), pacotes)
    return caminho


@pytest.fixture
def pcap_volume_alto(tmp_path: Path) -> Path:
    """PCAP onde um host excede o limiar de volume de bytes."""
    caminho = tmp_path / "volume_alto.pcap"
    pacotes = []
    for indice in range(12):
        pacotes.append(
            fabricar_pacote(indice * 0.1, "10.0.0.99", "10.0.0.1", 6, 1500)
        )
        pacotes.append(
            fabricar_pacote(indice * 0.1 + 0.05, "10.0.0.1", "10.0.0.99", 6, 1500)
        )
    wrpcap(str(caminho), pacotes)
    return caminho


@pytest.fixture
def pcap_protocolo_dominante(tmp_path: Path) -> Path:
    """PCAP com muitos pacotes TCP, acima do limiar de protocolo."""
    caminho = tmp_path / "protocolo_dominante.pcap"
    pacotes = [
        fabricar_pacote(indice * 0.1, "10.0.0.1", "10.0.0.2", 6, 100)
        for indice in range(40)
    ] + [
        fabricar_pacote(indice * 0.1, "10.0.0.2", "10.0.0.1", 17, 80)
        for indice in range(3)
    ]
    wrpcap(str(caminho), pacotes)
    return caminho


@pytest.fixture
def pcap_vazio(tmp_path: Path) -> Path:
    """PCAP sem pacotes."""
    caminho = tmp_path / "vazio.pcap"
    wrpcap(str(caminho), [])
    return caminho


@pytest.fixture
def pcap_com_arp(tmp_path: Path) -> Path:
    """PCAP com pacotes IP e um pacote ARP (sem camada IP, deve ser ignorado)."""
    caminho = tmp_path / "com_arp.pcap"
    pacotes = [
        fabricar_pacote(0.0, "10.0.0.1", "10.0.0.2", 6, 80),
        Ether() / ARP(),
    ]
    wrpcap(str(caminho), pacotes)
    return caminho
