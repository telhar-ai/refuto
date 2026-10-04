#!/bin/sh
# Instala los ganchos de git versionados de este repositorio. Idempotente.
#
#     sh scripts/install_hooks.sh
#
# Apunta `core.hooksPath` a `.githooks/`, que SÍ se versiona — a diferencia de `.git/hooks/`,
# que es local y se pierde en cada clon. Así el gancho viaja con el repositorio y se puede
# revisar en un PR como cualquier otro código.
#
# Lo que NO hace: no sustituye a la protección de ramas del servidor. Ver `.githooks/pre-push`
# para la medición de por qué no la hay, y `docs/operations/DEVSECOPS.md` para qué la daría.
set -eu

raiz=$(git rev-parse --show-toplevel 2>/dev/null) || {
    echo "  ✗ esto no es un repositorio git" >&2
    exit 1
}
cd "$raiz"

chmod +x .githooks/* 2>/dev/null || true
git config core.hooksPath .githooks

echo "  ✓ core.hooksPath → .githooks"
echo "    ganchos activos:"
for h in .githooks/*; do
    [ -f "$h" ] && printf "      %-14s %s\n" "$(basename "$h")" \
        "$(sed -n '2s/^# //p' "$h")"
done
echo
echo "    Comprobación: \`git push origin main\` debe rechazarse desde una rama de trabajo."
