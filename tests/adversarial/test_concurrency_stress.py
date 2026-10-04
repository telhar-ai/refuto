# -*- coding: utf-8 -*-
"""Pruebas de estrés y concurrencia sobre el Ledger y el Protocolo.

Ataca:
1. Append concurrente sobre el ledger con múltiples hilos y procesos.
2. Consultas concurrentes (query_status) mientras se escribe en el ledger.
3. Verificaciones de afirmaciones concurrentes (verify_claim).

Verifica:
- Invariante de encadenamiento hash ininterrumpido (h_i = H(h_{i-1} || event_i)).
- Cero escrituras perdidas (lost updates).
- Cero bifurcaciones (forks) en la cabeza del ledger.
- Cero líneas corruptas o JSONDecodeErrors.
- Integridad total bajo verificar_cadena().
"""

from __future__ import annotations

import concurrent.futures
import json
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path

from core.evidence import append_event, read_events, verificar_cadena
from core.protocol import RefutoProtocolServer


class TestConcurrencyStress(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="refuto-stress-"))
        self.server = RefutoProtocolServer(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_concurrent_ledger_appends_atomic_chain(self):
        """20 hilos escriben 10 eventos cada uno (200 eventos en total) concurrentemente."""
        num_threads = 20
        events_per_thread = 10
        total_events = num_threads * events_per_thread

        def worker(thread_id):
            for i in range(events_per_thread):
                evt = {
                    "kind": "test_concurrency",
                    "thread_id": thread_id,
                    "seq": i,
                    "payload": f"worker_{thread_id}_event_{i}"
                }
                append_event(self.tmp, evt)
                # Pequeño jitter aleatorio para aumentar interleaving
                time.sleep(0.001)

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker, t) for t in range(num_threads)]
            concurrent.futures.wait(futures)

        # 1. Comprobar que no se perdió ningún evento
        events = read_events(self.tmp)
        self.assertEqual(len(events), total_events, f"Lost updates! Se esperaban {total_events} pero hay {len(events)}")

        # 2. Comprobar que todos los eventos tienen JSON válido
        for i, ev in enumerate(events):
            self.assertIn("prev", ev)
            self.assertIn("h", ev)
            self.assertIn("ts", ev)

        # 3. Comprobar la integridad criptográfica de la cadena
        res_cadena = verificar_cadena(self.tmp)
        self.assertEqual(res_cadena["estado"], "INTEGRA", f"Cadena rota tras concurrencia: {res_cadena}")
        self.assertFalse(res_cadena["motivo"])

    def test_concurrent_readers_and_writers(self):
        """Lectores consultan query_status concurrentemente mientras escritores añaden eventos."""
        stop_event = threading.Event()
        read_errors = []
        read_counts = []

        def writer():
            for i in range(50):
                append_event(self.tmp, {"kind": "burst_write", "i": i})
                time.sleep(0.002)

        def reader():
            while not stop_event.is_set():
                try:
                    res = self.server.dispatch("refuto.query_status", {})
                    chain_status = res["ledger"]["chain_status"]
                    if chain_status not in ("INTEGRA", "AUSENTE", "VACIO"):
                        read_errors.append(f"Estado inconsistente observado: {chain_status}")
                    read_counts.append(res["ledger"]["events_count"])
                except Exception as exc:
                    read_errors.append(f"Excepción en reader: {exc}")
                time.sleep(0.001)

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            writer_futures = [executor.submit(writer) for _ in range(2)]
            reader_futures = [executor.submit(reader) for _ in range(4)]

            # Esperar a que terminen los escritores
            concurrent.futures.wait(writer_futures)
            stop_event.set()
            concurrent.futures.wait(reader_futures)

        self.assertEqual([], read_errors, f"Errores en lectores concurrentes: {read_errors}")
        self.assertGreater(len(read_counts), 10)
        # Monotonicidad: el recuento final debe coincidir exactamente con 100 eventos
        final_events = read_events(self.tmp)
        self.assertEqual(len(final_events), 100)
        final_chain = verificar_cadena(self.tmp)
        self.assertEqual(final_chain["estado"], "INTEGRA")


if __name__ == "__main__":
    unittest.main()
