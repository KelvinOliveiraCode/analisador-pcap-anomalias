"""Interface de linha de comando do analisador de PCAP."""

from __future__ import annotations

import argparse
from pathlib import Path

from .analisador import ler_pcap
from .detector import detectar_anomalias
from .relatorio import gerar_relatorio, salvar_relatorio

LIMIAR_VOLUME_PADRAO = 1_000_000
LIMIAR_PROTOCOLO_PADRAO = 100


def montar_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analisador-pcap",
        description="Lê um arquivo PCAP e reporta anomalias de volume e protocolo.",
    )
    parser.add_argument(
        "pcap",
        type=Path,
        help="Caminho do arquivo PCAP a analisar.",
    )
    parser.add_argument(
        "--limiar-volume",
        type=int,
        default=LIMIAR_VOLUME_PADRAO,
        help="Limiar de bytes por host para flagar anomalias de volume.",
    )
    parser.add_argument(
        "--limiar-protocolo",
        type=int,
        default=LIMIAR_PROTOCOLO_PADRAO,
        help="Limiar de pacotes por protocolo para flagar anomalias de protocolo.",
    )
    parser.add_argument(
        "--saida",
        type=Path,
        default=None,
        help="Caminho opcional para salvar o relatório em arquivo.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = montar_parser()
    args = parser.parse_args(argv)
    pacotes = ler_pcap(args.pcap)
    total_bytes = sum(pkt.tamanho for pkt in pacotes)
    anomalias = detectar_anomalias(
        pacotes, args.limiar_volume, args.limiar_protocolo
    )
    relatorio = gerar_relatorio(anomalias, len(pacotes), total_bytes)
    print(relatorio)
    if args.saida is not None:
        salvar_relatorio(relatorio, args.saida)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
