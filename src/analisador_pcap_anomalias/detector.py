"""Detecção de anomalias de volume e protocolo no tráfego capturado."""

from __future__ import annotations

from dataclasses import dataclass

from .analisador import Pacote


@dataclass(frozen=True)
class Anomalia:
    """Uma anomalia encontrada no tráfego."""

    tipo: str  # "volume" ou "protocolo"
    alvo: str  # endereço IP ou nome do protocolo
    protocolo: str | None
    pacotes: int
    bytes: int
    limiar: float
    gravidade: str  # "baixa", "media" ou "alta"
    descricao: str


def _gravidade(valor: int, limiar: float) -> str:
    if limiar <= 0:
        return "alta"
    proporcao = valor / limiar
    if proporcao >= 5:
        return "alta"
    if proporcao >= 2:
        return "media"
    return "baixa"


def detectar_volume(pacotes: list[Pacote], limiar_bytes: int) -> list[Anomalia]:
    """Detecta hosts cujo total de bytes (origem + destino) excede o limiar."""
    if limiar_bytes < 0:
        raise ValueError("limiar_bytes não pode ser negativo")
    volumes: dict[str, int] = {}
    contagem: dict[str, int] = {}
    for pkt in pacotes:
        for host in (pkt.origem, pkt.destino):
            volumes[host] = volumes.get(host, 0) + pkt.tamanho
            contagem[host] = contagem.get(host, 0) + 1
    anomalias: list[Anomalia] = []
    for host, total in volumes.items():
        if total > limiar_bytes:
            anomalias.append(
                Anomalia(
                    tipo="volume",
                    alvo=host,
                    protocolo=None,
                    pacotes=contagem[host],
                    bytes=total,
                    limiar=float(limiar_bytes),
                    gravidade=_gravidade(total, limiar_bytes),
                    descricao=(
                        f"Host {host} excedeu o limiar de volume "
                        f"({total} bytes > {limiar_bytes})."
                    ),
                )
            )
    anomalias.sort(key=lambda a: a.bytes, reverse=True)
    return anomalias


def detectar_protocolo(pacotes: list[Pacote], limiar_pacotes: int) -> list[Anomalia]:
    """Detecta protocolos cujo número de pacotes excede o limiar."""
    if limiar_pacotes < 0:
        raise ValueError("limiar_pacotes não pode ser negativo")
    contagem: dict[str, int] = {}
    bytes_por_protocolo: dict[str, int] = {}
    for pkt in pacotes:
        contagem[pkt.protocolo] = contagem.get(pkt.protocolo, 0) + 1
        bytes_por_protocolo[pkt.protocolo] = (
            bytes_por_protocolo.get(pkt.protocolo, 0) + pkt.tamanho
        )
    anomalias: list[Anomalia] = []
    for protocolo, qtd in contagem.items():
        if qtd > limiar_pacotes:
            anomalias.append(
                Anomalia(
                    tipo="protocolo",
                    alvo=protocolo,
                    protocolo=protocolo,
                    pacotes=qtd,
                    bytes=bytes_por_protocolo[protocolo],
                    limiar=float(limiar_pacotes),
                    gravidade=_gravidade(qtd, limiar_pacotes),
                    descricao=(
                        f"Protocolo {protocolo} excedeu o limiar de pacotes "
                        f"({qtd} > {limiar_pacotes})."
                    ),
                )
            )
    anomalias.sort(key=lambda a: a.pacotes, reverse=True)
    return anomalias


def detectar_anomalias(
    pacotes: list[Pacote],
    limiar_volume_bytes: int,
    limiar_protocolo_pacotes: int,
) -> list[Anomalia]:
    """Executa detecção de volume e protocolo e devolve todas as anomalias."""
    return detectar_volume(pacotes, limiar_volume_bytes) + detectar_protocolo(
        pacotes, limiar_protocolo_pacotes
    )
