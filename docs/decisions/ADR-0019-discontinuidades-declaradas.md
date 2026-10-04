# ADR-0019 · Una rotura reconocida se declara; no se borra ni se ignora

**Estado:** aceptado · **Fecha:** 2026-09-28 · **Implementación:** `core/evidence.py`
(`CICATRIZADA`, `discontinuidades`, `verificar_cadena`), `core/concordia.py` (`anclar`),
`refuto.py` (`status`).

## Contexto

Medido el 2026-09-28 en un espacio real de 13.063 eventos: **dos** roturas de la cadena, las dos
del **2026-09-24**, y las dos con la misma firma — dos eventos con el mismo `prev` y milisegundos
de diferencia. Es la carrera de concurrencia del guardián: dos procesos leen la misma cabeza y
encadenan los dos a ella. Se cerró el **2026-09-25** (`7eb0945`, «leer la cabeza y escribir el
eslabón son una sola operación»).

Ninguna huella estaba alterada: los cuatro eventos implicados reproducen su propio digest. Es
decir, el diario decía «manipulación» de algo que fue concurrencia, causada por un defecto que ya
no existe. Y lo decía **para siempre**: `status` daba `NO INTEGRABLE` en cada corrida, y el
espacio no podía volver a operar nunca.

Eso deja dos salidas malas. Convivir con una alarma permanente —hasta aprender a ignorarla, que
es el modo de muerte que este repositorio ya documentó en `core.policy._partir` y en `dd:*`—, o
**borrar el diario**, que es la manipulación más simple que existe y la que la cadena existe para
hacer visible. El sistema empujaba hacia la peor de las dos.

El precedente estaba escrito: los eventos de `legado` —sin `prev`/`h`, de antes de que la cadena
existiera— se toleran, y el motivo declarado es literal: *«tratarlos como rotos convertiría toda
instalación previa en sospechosa el día de la actualización, que es como se enseña a ignorar una
alarma»*. Lo que faltaba era el equivalente para una rotura posterior y concreta.

## Decisión

1. **Una discontinuidad se DECLARA**, en `.harness/evidence/discontinuities/declared.json`, con
   `line`, `found_prev`, `expected_head`, `cause`, `declared_by` y `declared_at`. Los seis
   campos, sin valores por omisión: una declaración a medias no se puede contrastar con la
   rotura que dice explicar. El fichero vive bajo `evidence/`, que la política protege — lo
   escribe **una persona**.
2. **Sólo surte efecto si coincide exactamente**: misma línea, mismo `prev` encontrado y misma
   cabeza que se esperaba. No hay comodines ni rangos.
3. **La huella se sigue exigiendo**, y con el `prev` que el evento declara. Lo que la cicatriz
   autoriza es el **salto**, nunca un contenido incoherente. (Sin esta precisión, la primera
   implementación acusaba de «editado después» a un evento auténtico: medido con el diario real.)
4. **Estado propio: `CICATRIZADA`.** No es `INTEGRA` —el tramo anterior a una cicatriz no está
   atado al posterior— y no es `ROTA` —las discontinuidades son exactamente las declaradas—.
   `ok=True`, porque la cadena se sostiene por tramos y quien lo lea tiene que poder seguir
   trabajando; y visible siempre, con la línea, los digests, la causa y quién la reconoció.
5. **Quien exige integridad total lo distingue sin leer una lista.** `anclar` devuelve `BLOCKED`
   sobre una cadena cicatrizada, antes de abrir ninguna conexión: un ancla afirma «el diario
   medía n y su cabeza era h», y con un salto en medio eso es más de lo que la cadena sostiene.
6. **`status` no la llama fallo.** Un texto que diga «no se sostiene» de algo que una persona ya
   reconoció empuja a buscar la forma de que desaparezca, que es de donde veníamos.

## Por qué esto no abre una puerta

| intento | qué pasa |
|---|---|
| editar un evento después de declarar la cicatriz | `ROTA` — la huella no cuadra, y eso lo caza otra comprobación |
| borrar un evento | `ROTA` — las líneas se desplazan y la declaración deja de casar |
| insertar un evento | `ROTA` — ídem |
| truncar la cola | `DESALINEADA` frente al ancla publicada; una declaración no lo toca |
| declarar una rotura que no existe | no pasa nada: la cadena sigue `INTEGRA` |
| una sola declaración para dos roturas | `ROTA` en la segunda: cada una necesita la suya |
| declaración ilegible, de otro esquema o incompleta | se ignora y **se dice**; nada se amnistía |

Las siete están en `tests/adversarial/test_discontinuidades.py`, y son la mitad del fichero: lo
que había que demostrar no es que el mecanismo funcione, sino que no sirve para nada más.

## Límites que esta decisión NO cierra

- **No repara nada.** Una cicatriz no ata el tramo anterior al posterior; lo hace explícito.
- **La declaración es tan buena como quien la firma.** Con `uid(S) = uid(J)`, quien escriba el
  diario puede escribir también la declaración. Lo que se gana es que la discontinuidad quede
  **nombrada, fechada y atribuida** en vez de borrada — tamper-evidencia, como el resto.
- **Un espacio cicatrizado no se ancla** hasta que exista un tramo nuevo que anclar. Es una
  consecuencia buscada, no un efecto colateral.
- **Nada obliga a declarar la causa correcta.** El texto no se verifica; lo que se verifica es
  que la rotura sea exactamente la descrita.

## Qué la haría cambiar

Que el ancla aprenda a certificar **tramos** en vez de la cadena entera. Entonces un espacio con
cicatrices podría anclar el tramo vigente, y el punto 5 dejaría de ser un bloqueo para pasar a
ser una acotación del alcance de cada ancla.
