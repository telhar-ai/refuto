# ADR-0008 · La matriz de compatibilidad se genera; no se escribe

**Estado:** aceptado · **Fecha:** 2026-08-27

## Problema

Una matriz de compatibilidad escrita a mano es correcta el día que se escribe y mentira tres
versiones después. Y miente en la dirección peligrosa: sigue diciendo «soportado» cuando ya no
lo está, porque nadie vuelve a mirarla. Nadie audita una tabla en verde.

## Decisión

```
agente instalado → sonda → adapter → matriz → SUPPORT_MATRIX.md
```

`refuto docs` sondea la máquina y escribe la matriz. Sólo puede afirmar lo que la máquina acaba
de demostrar.

Siete valores, y cada uno dice de dónde salió la casilla:

| Valor | Significa |
|---|---|
| `NATIVO` | lo trae el agente y se comprobó ejecutándolo |
| `COMPROBADO` | el agente lo declaró en su propio handshake |
| `ADAPTER` | lo aporta refuto traduciendo |
| `DECLARADO` | consta en la documentación del CLI instalado; no se sondeó |
| `NO` | consta que no existe |
| `BLOQUEADO` | no se pudo verificar: el agente no arranca en esta máquina |
| `?` | no verificado. Se declara; no se rellena |

## Consecuencias

- La matriz generada hoy dice **35 de 50 casillas verificadas, 15 declaradas sin verificar**.
  Una tabla escrita a mano habría tenido 50 casillas llenas y no habría sido más cierta.
- Toda la columna de Codex sale `BLOQUEADO`. Es correcto y es la lectura útil: el adapter existe
  y está bien escrito; lo que no existe es evidencia de que funcione.
- La matriz se regenera en cada máquina. Dos ingenieros con instalaciones distintas obtienen
  matrices distintas, **que es la verdad**. Una matriz única para todos sería una ficción
  compartida.
