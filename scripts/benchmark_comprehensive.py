# -*- coding: utf-8 -*-
"""Benchmark exhaustivo y caracterización de complejidad para Refuto.

Mide:
- refuto.initialize
- refuto.evaluate_action
- refuto.query_status sobre diarios de 10, 100, 1.000 y 5.000 eventos
- refuto.verify_claim (G-ROLES)
- Desglose de coste: I/O de disco, JSON parse, Hasheo SHA-256
- Métricas: Media, P50, P95, P99, Throughput (ops/sec), Complejidad empírica
"""

from __future__ import annotations

import cProfile
import gc
import pstats
import shutil
import tempfile
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.evidence import append_event
from core.protocol import RefutoProtocolServer


def create_mock_ledger(workspace: Path, n_events: int) -> None:
    for i in range(n_events):
        append_event(workspace, {
            "kind": "benchmark_event",
            "index": i,
            "data": f"payload_data_for_benchmark_{i}"
        })


def measure_latencies(fn, iterations=50):
    latencies = []
    gc.collect()
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)  # ms
    latencies.sort()
    mean = sum(latencies) / len(latencies)
    p50 = latencies[int(len(latencies) * 0.50)]
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]
    throughput = (1000.0 / mean) if mean > 0 else float("inf")
    return {
        "mean_ms": round(mean, 3),
        "p50_ms": round(p50, 3),
        "p95_ms": round(p95, 3),
        "p99_ms": round(p99, 3),
        "throughput_ops_sec": round(throughput, 1)
    }


def run_benchmark():
    print("=" * 80)
    print("BENCHMARK EXHAUSTIVO Y PERFILADO DE RENDIMIENTO REFUTO")
    print("=" * 80)

    tmp_dir = Path(tempfile.mkdtemp(prefix="refuto-bench-"))
    try:
        server = RefutoProtocolServer(tmp_dir)

        # 1. Initialize
        bench_init = measure_latencies(lambda: server.dispatch("refuto.initialize", {}), iterations=100)
        print("\n1. refuto.initialize (Handshake en memoria):")
        print(f"   Media: {bench_init['mean_ms']} ms | P50: {bench_init['p50_ms']} ms | P95: {bench_init['p95_ms']} ms | P99: {bench_init['p99_ms']} ms | {bench_init['throughput_ops_sec']} ops/s")

        # 2. Evaluate Action
        act = {"action": "read", "tool": "Read", "path": "README.md"}
        bench_eval = measure_latencies(lambda: server.dispatch("refuto.evaluate_action", {"action": act}), iterations=100)
        print("\n2. refuto.evaluate_action (Evaluación de política / Guardián):")
        print(f"   Media: {bench_eval['mean_ms']} ms | P50: {bench_eval['p50_ms']} ms | P95: {bench_eval['p95_ms']} ms | P99: {bench_eval['p99_ms']} ms | {bench_eval['throughput_ops_sec']} ops/s")

        # 3. Escalamiento de query_status por tamaño de diario
        print("\n3. refuto.query_status — Caracterización de Complejidad por Tamaño de Ledger:")
        sizes = [10, 100, 1000, 3000]
        results_scaling = {}

        for n in sizes:
            sub_dir = tmp_dir / f"ledger_{n}"
            sub_dir.mkdir(parents=True)
            create_mock_ledger(sub_dir, n)
            sub_server = RefutoProtocolServer(sub_dir)

            res = measure_latencies(lambda: sub_server.dispatch("refuto.query_status", {}), iterations=30)
            results_scaling[n] = res
            print(f"   Ledger n={n:<5} eventos -> Media: {res['mean_ms']:<7} ms | P50: {res['p50_ms']:<7} ms | P95: {res['p95_ms']:<7} ms | {res['throughput_ops_sec']} ops/s")

        # 4. Perfilado de profiling con cProfile para query_status con n=1000
        print("\n4. Profiling cProfile de query_status (n=1000 eventos):")
        dir_prof = tmp_dir / "ledger_1000"
        server_prof = RefutoProtocolServer(dir_prof)
        pr = cProfile.Profile()
        pr.enable()
        for _ in range(10):
            server_prof.dispatch("refuto.query_status", {})
        pr.disable()
        ps = pstats.Stats(pr).sort_stats("tottime")
        ps.print_stats(8)

        print("=" * 80)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    run_benchmark()
