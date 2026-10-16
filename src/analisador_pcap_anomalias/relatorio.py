"""Geração de relatório textual de anomalias."""

from __future__ import annotations

from pathlib import Path

from .analisador import Pacote
from .detector import Anomalia


def gerar_relatorio(
    anomalias: list[Anomalia],
    total_pacotes: int,
    total_bytes: int,
) -> str:
    """Monta o relatório textual de anomalias."""
    linhas: list[str] = []
    linhas.append("RELATÓRIO DE ANOMALIAS — PCAP")
    linhas.append("=" * 40)
    linhas.append(f"Pacotes analisados: {total_pacotes}")
    linhas.append(f"Bytes totais: {total_bytes}")
    linhas.append("")
    if not anomalias:
        linhas.append("Nenhuma anomalia detectada.")
    else:
        linhas.append(f"Anomalias encontradas: {len(anomalias)}")
        linhas.append("")
        for anomalia in anomalias:
            linhas.append(
                f"[{anomalia.gravidade.upper()}] {anomalia.tipo}: "
                f"{anomalia.alvo} "
                f"(pacotes={anomalia.pacotes}, bytes={anomalia.bytes}, "
                f"limiar={anomalia.limiar:.0f})"
            )
            linhas.append(f"    {anomalia.descricao}")
    linhas.append("")
    linhas.append("Fim do relatório.")
    return "\n".join(linhas)


def salvar_relatorio(conteudo: str, caminho: str | Path) -> None:
    """Escreve o conteúdo do relatório em um arquivo UTF-8."""
    Path(caminho).write_text(conteudo, encoding="utf-8")
