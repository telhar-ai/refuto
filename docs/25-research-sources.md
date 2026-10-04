# Fuentes Científicas y Bibliografía de Referencia

Este documento recopila las referencias científicas, estándares industriales y fuentes primarias que fundamentan la arquitectura, modelos epistemológicos y mecanismos criptográficos de Refuto.

---

## 1. Filosofía de la Ciencia y Epistemología de la Verificación

1. **Popper, Karl R.** (1934). *Logik der Forschung: Zur Erkenntnistheorie der modernen Naturwissenschaft*. Springer, Viena. (Trad. inglesa: *The Logic of Scientific Discovery*, Hutchinson, 1959).
   - *Aporte a Refuto*: Principio rector de la falsabilidad; la verificación positiva es asimétrica frente a la refutación por contraejemplo.
2. **Lakatos, Imre.** (1976). *Proofs and Refutations: The Logic of Mathematical Discovery*. Cambridge University Press.
   - *Aporte a Refuto*: Proceso iterativo de refinamiento de conjeturas mediante contraejemplos e incorporación de lemas reductores.
3. **Mayo, Deborah G., & Spanos, Aris.** (2011). *Error and Inference: Recent Advances in Reliability, Testing, and Realism*. Cambridge University Press.
   - *Aporte a Refuto*: Teoría formal de la Severidad de la Prueba ($S$): una prueba sólo corrobora una afirmación si ha tenido alta probabilidad de detectar una falla en caso de existir.

---

## 2. Métodos Formales, Semántica y Verificación de Software

4. **Hoare, C. A. R.** (1969). *An Axiomatic Basis for Computer Programming*. Communications of the ACM, 12(10), 576–580.
   - *Aporte a Refuto*: Lógica de tripletas $\{P\} C \{Q\}$ aplicada a las precondiciones, transformaciones y poscondiciones de las compuertas.
5. **Dijkstra, Edsger W.** (1976). *A Discipline of Programming*. Prentice-Hall.
   - *Aporte a Refuto*: Cálculo de precondiciones más débiles (*weakest preconditions*) y el axioma de que las pruebas sólo demuestran la presencia de errores, no su ausencia.
6. **Necula, George C.** (1997). *Proof-Carrying Code (PCC)*. Proceedings of the 24th ACM SIGPLAN-SIGACT Symposium on Principles of Programming Languages (POPL '97), 106–119.
   - *Aporte a Refuto*: Fundamento de la **Cápsula de Decisión**: el productor del código debe adjuntar una atestación verificable de manera rápida e independiente por el consumidor.
7. **Lamport, Leslie.** (2002). *Specifying Systems: The TLA+ Language and Tools for Hardware and Software Engineers*. Addison-Wesley.
   - *Aporte a Refuto*: Modelado formal de invariantes temporales y estados de transición en sistemas concurrentes y protocolos de consenso.

---

## 3. Pruebas de Software, Falsación Mutacional y Metamórfica

8. **DeMillo, Richard A., Lipton, Richard J., & Sayward, Frederick G.** (1978). *Hints on Test Data Selection: The Coupling Hypothesis*. IEEE Computer, 11(4), 34–41.
   - *Aporte a Refuto*: Hipótesis del Acoplamiento y el Efecto del Programador Competente que justifican el análisis de mutantes de primer orden.
9. **Jia, Yue, & Harman, Mark.** (2011). *An Analysis and Survey of the Development of Mutation Testing*. IEEE Transactions on Software Engineering, 37(5), 649–678.
   - *Aporte a Refuto*: Taxonomía de operadores de mutación y métricas de puntaje de mutación ($MS$).
10. **Chen, Tsong Yueh, Cheung, Shing Chi, & Yiu, S. M.** (1998). *Metamorphic Testing: A New Approach for Generating Next Test Cases*. Technical Report HKUST-CS98-01, Hong Kong University of Science and Technology.
    - *Aporte a Refuto*: Resolución del Problema del Oráculo en dominios estocásticos y de IA mediante relaciones metamórficas.
11. **Claessen, Koen, & Hughes, John.** (2000). *QuickCheck: A Lightweight Tool for Random Testing of Haskell Programs*. ACM SIGPLAN Notices, 35(9), 268–279.
    - *Aporte a Refuto*: Generación estocástica de casos de prueba basada en propiedades e invariantes universales con reducción automática (*shrinking*).

---

## 4. Estándares de Casos de Aseguramiento y Seguridad de Sistemas

12. **Origin Consulting & York University.** (2018). *Goal Structuring Notation (GSN) Community Standard Version 2*. SCSC (Safety-Critical Systems Club).
    - *Aporte a Refuto*: Grafo ontológico de justificación de seguridad (Objetivo $\to$ Estrategia $\to$ Solución/Evidencia).
13. **ISO/IEC 26262.** (2018). *Road vehicles — Functional safety*. International Organization for Standardization.
    - *Aporte a Refuto*: Niveles de Integridad de Seguridad Automotriz (ASIL) y matrices de trazabilidad bidireccional de requisitos a pruebas.
14. **RTCA DO-178C / EUROCAE ED-12C.** (2011). *Software Considerations in Airborne Systems and Equipment Certification*.
    - *Aporte a Refuto*: Principio de cobertura estructural con independencia de oráculos y no-vacuidad del alcance evaluado (MC/DC).

---

## 5. Seguridad de Cadena de Suministro y Procedencia Criptográfica

15. **Torres-Arias, Santiago, et al.** (2019). *in-toto: Providing Farm-to-Table Guarantees for Bits and Bytes*. USENIX Security Symposium 2019, 1393–1410.
    - *Aporte a Refuto*: Especificación de atestaciones de diseño y pasos de construcción con verificación de llaves y enlaces de productos.
16. **OpenSSF.** (2023). *Supply-chain Levels for Software Artifacts (SLSA) v1.0 Specification*. Open Source Security Foundation.
    - *Aporte a Refuto*: Modelo de procedencia de compilación, inmutabilidad de artefactos y prevención de modificaciones fuera de banda.
17. **Laurie, Ben, Langley, Adam, & Kasper, Emilia.** (2013). *RFC 6962: Certificate Transparency*. Internet Engineering Task Force (IETF).
    - *Aporte a Refuto*: Estructura de libro mayor append-only con árboles Merkle y monitores públicos para auditoría de atestaciones.
18. **NIST.** (2022). *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities*. NIST Special Publication 800-218.
    - *Aporte a Refuto*: Controles de integridad y atestación de prácticas seguras de ingeniería.

---

## 6. Verificación en Tiempo de Ejecución y Observabilidad

19. **Pnueli, Amir.** (1977). *The Temporal Logic of Programs*. 18th Annual Symposium on Foundations of Computer Science (FOCS 1977), 46–57.
    - *Aporte a Refuto*: Lógica temporal lineal (LTL) para la especificación y monitoreo de propiedades que deben cumplirse a lo largo del tiempo de ejecución.
20. **Havelund, Klaus, & Goldberg, Allen.** (2005). *Verify Your Runs*. Verified Software: Theories, Tools, Experiments (VSTTE 2005), LNCS 4171, 374–383.
    - *Aporte a Refuto*: Principios de instrumentación de monitores de tiempo de ejecución sin introducir degradación catastrófica de rendimiento.

---

## 7. Sistemas Distribuidos y Consenso Bizantino

21. **Castro, Miguel, & Liskov, Barbara.** (2002). *Practical Byzantine Fault Tolerance and Proactive Recovery*. ACM Transactions on Computer Systems (TOCS), 20(4), 398–461.
    - *Aporte a Refuto*: Algoritmo de consenso de la red notarial Concordia frente a nodos y agentes maliciosos o corruptos ($3f + 1$).
22. **Danezis, George, et al.** (2022). *Narwhal and Bullshark: Disaggregated Mempool and Efficient BFT Consensus*. EuroSys '22, 511–528.
    - *Aporte a Refuto*: Desacoplamiento de la disponibilidad de datos (memoria de evidencias) respecto a la secuenciación del consenso notarial.

---

## 8. Marcos Contemporáneos de Ingeniería Asistida por IA

23. **Amazon Web Services.** (2025). *AWS AI-DLC: AI Development Lifecycle Framework (v2.10)*. AWS Labs Technical Documentation & Source Code (`awslabs/aidlc-workflows`).
    - *Aporte a Refuto*: Mapeo de etapas, directivas de orquestación basadas en Bun/TypeScript y separación entre el Conductor y los comandos de verificación.
24. **European Parliament and Council.** (2024). *Artificial Intelligence Act (Regulation EU 2024/1689)*. Official Journal of the European Union.
    - *Aporte a Refuto*: Requisitos regulatorios de trazabilidad, robustez técnica y supervisión humana vinculados al modelo de paquetes de políticas de Refuto.
