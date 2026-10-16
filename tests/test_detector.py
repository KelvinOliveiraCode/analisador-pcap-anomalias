"""Testes do módulo detector: anomalias de volume e protocolo."""

from __future__ import annotations

import pytest

from analisador_pcap_anomalias import (
    Anomalia,
    Pacote,
    detectar_anomalias,
    detectar_protocolo,
    detectar_volume,
)


def _pacote(ip_origem: str, ip_destino: str, protocolo: str, tamanho: int) -> Pacote:
    return Pacote(0.0, ip_origem, ip_destino, protocolo, tamanho)


def test_detectar_volume_host_acima_limiar(pcap_volume_alto) -> None:
    from analisador_pcap_anomalias import ler_pcap

    pacotes = ler_pcap(pcap_volume_alto)
    anomalias = detectar_volume(pacotes, limiar_bytes=20_000)
    assert len(anomalias) == 2
    assert {a.alvo for a in anomalias} == {"10.0.0.99", "10.0.0.1"}
    assert all(a.tipo == "volume" and a.bytes > 20_000 for a in anomalias)
    assert all(a.gravidade in ("baixa", "media", "alta") for a in anomalias)


def test_detectar_volume_abaixo_limiar_retorna_vazio(pcap_baixo_traffico) -> None:
    from analisador_pcap_anomalias import ler_pcap

    pacotes = ler_pcap(pcap_baixo_traffico)
    assert detectar_volume(pacotes, limiar_bytes=1_000_000) == []


def test_detectar_volume_limiar_negativo_erra() -> None:
    with pytest.raises(ValueError, match="limiar_bytes"):
        detectar_volume([], limiar_bytes=-1)


def test_detectar_protocolo_tcp_acima_limiar(pcap_protocolo_dominante) -> None:
    from analisador_pcap_anomalias import ler_pcap

    pacotes = ler_pcap(pcap_protocolo_dominante)
    anomalias = detectar_protocolo(pacotes, limiar_pacotes=10)
    assert len(anomalias) == 1
    anomalia = anomalias[0]
    assert anomalia.tipo == "protocolo"
    assert anomalia.alvo == "TCP"
    assert anomalia.pacotes == 40


def test_detectar_protocolo_abaixo_limiar_retorna_vazio(
    pcap_protocolo_dominante,
) -> None:
    from analisador_pcap_anomalias import ler_pcap

    pacotes = ler_pcap(pcap_protocolo_dominante)
    assert detectar_protocolo(pacotes, limiar_pacotes=100) == []


def test_detectar_protocolo_limiar_negativo_erra() -> None:
    with pytest.raises(ValueError, match="limiar_pacotes"):
        detectar_protocolo([], limiar_pacotes=-1)


def test_detectar_anomalias_combina_volume_e_protocolo(
    pcap_volume_alto, pcap_protocolo_dominante
) -> None:
    from analisador_pcap_anomalias import ler_pcap

    pacotes = ler_pcap(pcap_volume_alto) + ler_pcap(pcap_protocolo_dominante)
    anomalias = detectar_anomalias(
        pacotes, limiar_volume_bytes=20_000, limiar_protocolo_pacotes=10
    )
    tipos = {a.tipo for a in anomalias}
    assert "volume" in tipos
    assert "protocolo" in tipos


def test_detectar_anomalias_sem_entradas_retorna_vazio() -> None:
    assert detectar_anomalias([], 1000, 10) == []


def test_detectar_volume_conta_origem_e_destino() -> None:
    pacotes = [
        _pacote("10.0.0.1", "10.0.0.2", "TCP", 1000),
        _pacote("10.0.0.2", "10.0.0.1", "TCP", 1000),
    ]
    anomalias = detectar_volume(pacotes, limiar_bytes=1500)
    assert len(anomalias) == 2
    assert {a.alvo for a in anomalias} == {"10.0.0.1", "10.0.0.2"}


def test_anomalia_tem_campos_obrigatorios() -> None:
    anomalia = Anomalia(
        tipo="volume",
        alvo="10.0.0.99",
        protocolo=None,
        pacotes=24,
        bytes=36_000,
        limiar=20_000.0,
        gravidade="media",
        descricao="Host 10.0.0.99 excedeu o limiar de volume.",
    )
    assert anomalia.tipo == "volume"
    assert isinstance(anomalia.descricao, str)
