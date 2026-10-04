---
name: frontend
description: Construccion del producto con marcado semantico y estilos por tokens. Usar al escribir cualquier archivo de app/.
harness:
  version: 1.0.0
  requires:
    tools:
      - read
      - write
  compat:
    claude: verificado
    kiro: verificado
    gemini: no-verificado
---

# Construcción del producto

## Cero dependencias externas

Cada dependencia entra al inventario, hay que sostenerla y amplía la superficie a auditar.
Lo que se puede escribir en treinta líneas no se instala.

## La lógica se separa del documento

Las funciones de negocio no tocan el DOM: reciben datos y devuelven datos. Esa separación es
lo que permite probarlas sin navegador, y una prueba que necesita navegador para comprobar una
regla de negocio es una prueba que nadie va a correr en cada cambio.
