"""Testes do módulo analisador: leitura de PCAP e estatísticas."""

from __future__ import annotations

from pathlib import Path

import pytest

from analisador_pcap_anomalias import EstatisticaProtocolo, Pacote, ler_pcap
from .conftest import fabricar_pacote
from scapy.all import wrpcap


def test_ler_pcap_baixo_traffico(pcap_baixo_traffico: Path) -> None:
    pacotes = ler_pcap(pcap_baixo_traffico)
    assert len(pacotes) == 3
    assert all(isinstance(p, Pacote) for p in pacotes)


def test_ler_pcap_mapeia_protocolos_conhecidos(pcap_baixo_traffico: Path) -> None:
    pacotes = ler_pcap(pcap_baixo_traffico)
    assert [p.protocolo for p in pacotes] == ["TCP", "UDP", "ICMP"]


def test_ler_pcap_preenche_campos(pcap_baixo_traffico: Path) -> None:
    pacotes = ler_pcap(pcap_baixo_traffico)
    primeiro = pacotes[0]
    assert primeiro.origem == "10.0.0.1"
    assert primeiro.destino == "10.0.0.2"
    assert primeiro.timestamp == 0.0
    assert primeiro.tamanho >= 60  # Ethernet + IP + TCP


def test_ler_pcap_ignora_pacotes_sem_ip(pcap_com_arp: Path) -> None:
    pacotes = ler_pcap(pcap_com_arp)
    assert len(pacotes) == 1
    assert pacotes[0].protocolo == "TCP"


def test_ler_pcap_arquivo_inexistente() -> None:
    with pytest.raises(FileNotFoundError, match="Arquivo PCAP não encontrado"):
        ler_pcap(Path("nao_existe.pcap"))


def test_ler_pcap_vazio_retorna_lista_vazia(pcap_vazio: Path) -> None:
    assert ler_pcap(pcap_vazio) == []


def test_estatisticas_dataframe_estruture_saida(pcap_baixo_traffico: Path) -> None:
    from analisador_pcap_anomalias import estatisticas_dataframe

    df = estatisticas_dataframe(ler_pcap(pcap_baixo_traffico))
    assert list(df.columns) == ["protocolo", "pacotes", "bytes"]
    assert len(df) == 3
    assert df["protocolo"].tolist() == sorted(df["protocolo"].tolist())


def test_estatisticas_dataframe_vazio() -> None:
    from analisador_pcap_anomalias import estatisticas_dataframe

    df = estatisticas_dataframe([])
    assert list(df.columns) == ["protocolo", "pacotes", "bytes"]
    assert len(df) == 0


def test_estatisticas_dataframe_agrega_por_protocolo() -> None:
    from analisador_pcap_anomalias import estatisticas_dataframe

    pacotes = [
        Pacote(0.0, "10.0.0.1", "10.0.0.2", "TCP", 100),
        Pacote(0.1, "10.0.0.2", "10.0.0.1", "TCP", 200),
        Pacote(0.2, "10.0.0.1", "10.0.0.3", "UDP", 50),
    ]
    df = estatisticas_dataframe(pacotes)
    tcp = df[df["protocolo"] == "TCP"].iloc[0]
    udp = df[df["protocolo"] == "UDP"].iloc[0]
    assert tcp["pacotes"] == 2
    assert tcp["bytes"] == 300
    assert udp["pacotes"] == 1
    assert udp["bytes"] == 50


def test_estatisticas_dataframe_eh_deterministico() -> None:
    from analisador_pcap_anomalias import estatisticas_dataframe

    pacotes = [
        Pacote(float(i), "10.0.0.1", "10.0.0.2", proto, 100)
        for i, proto in enumerate(["UDP", "TCP", "ICMP", "TCP"])
    ]
    df1 = estatisticas_dataframe(pacotes)
    df2 = estatisticas_dataframe(list(reversed(pacotes)))
    pd_df1 = df1.sort_values("protocolo").reset_index(drop=True)
    pd_df2 = df2.sort_values("protocolo").reset_index(drop=True)
    assert pd_df1.equals(pd_df2)
