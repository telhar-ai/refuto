/**
 * Refuto AI-DLC Bridge (TypeScript / Bun / Node.js)
 * 
 * Interoperability bridge connecting AWS AI-DLC Stage Conductors with Refuto Wire Protocol v1.
 * Specification: docs/21-adapter-model.md
 */

import { spawn } from "node:child_process";
import * as path from "node:path";

export interface ScopeRequirement {
  min_examined?: number;
  universe?: string;
}

export interface Claim {
  schema: string;
  claim_id: string;
  property: string;
  subject?: Record<string, unknown>;
  scope_requirement?: ScopeRequirement;
  evidence_requirements?: Record<string, unknown>;
}

export interface DecisionCapsule {
  schema: string;
  decision_id: string;
  claim_id: string;
  status: "PASS" | "FAIL" | "BLOCKED" | "NOT_RUN" | "INCONCLUSIVE" | "DEGRADED" | "NOT_APPLICABLE";
  epistemic_level: "E0" | "E1" | "E2" | "E3" | "E4";
  scope: {
    items_examined: number;
    min_required: number;
    unscoped_gates: string[];
    declared: boolean;
  };
  verdict_rationale: string;
  ledger_head?: string;
  subject_digest: string;
  timestamp: string;
  gates: Array<Record<string, unknown>>;
}

export interface AdmissibilityResult {
  admitted: boolean;
  stage: string;
  capsule?: DecisionCapsule;
  remediation_actions: string[];
  error?: string;
}

/**
 * Verifies stage admissibility by dispatching a formal Claim to Refuto via stdio JSON-RPC 2.0.
 */
export async function verifyStageAdmissibility(
  stage: string,
  workspacePath: string,
  options?: {
    pythonBinary?: string;
    refutoCliPath?: string;
    minExamined?: number;
    claimId?: string;
  }
): Promise<AdmissibilityResult> {
  const pythonBin = options?.pythonBinary ?? "python3";
  const refutoPath = options?.refutoCliPath ?? path.resolve(workspacePath, "refuto.py");
  const claimId = options?.claimId ?? `clm_aidlc_${stage.toLowerCase()}_${Date.now()}`;
  const minExamined = options?.minExamined ?? 1;

  const claim: Claim = {
    schema: "refuto.claim/v1",
    claim_id: claimId,
    property: `lifecycle.stage_admissibility.${stage.toLowerCase()}`,
    scope_requirement: { min_examined: minExamined }
  };

  const rpcRequest = {
    jsonrpc: "2.0",
    method: "refuto.verify_claim",
    params: {
      claim,
      stage
    },
    id: 1
  };

  return new Promise<AdmissibilityResult>((resolve) => {
    let proc;
    try {
      proc = spawn(pythonBin, [refutoPath, "--workspace", workspacePath, "protocol"], {
        stdio: ["pipe", "pipe", "pipe"]
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      return resolve({
        admitted: false,
        stage,
        remediation_actions: ["Verificar que python3 y refuto.py están disponibles"],
        error: `Error iniciando proceso Refuto: ${message}`
      });
    }

    let stdoutData = "";
    let stderrData = "";

    proc.stdout.on("data", (chunk: Buffer) => {
      stdoutData += chunk.toString("utf-8");
    });

    proc.stderr.on("data", (chunk: Buffer) => {
      stderrData += chunk.toString("utf-8");
    });

    proc.on("close", (code: number) => {
      if (code !== 0 && !stdoutData.trim()) {
        return resolve({
          admitted: false,
          stage,
          remediation_actions: ["Revisar logs de ejecución del servidor de protocolo Refuto"],
          error: `Proceso Refuto terminó con código ${code}: ${stderrData}`
        });
      }

      try {
        const responseLine = stdoutData.trim().split("\n")[0];
        const rpcResponse = JSON.parse(responseLine);

        if (rpcResponse.error) {
          return resolve({
            admitted: false,
            stage,
            remediation_actions: [rpcResponse.error.message],
            error: `Error RPC Refuto (${rpcResponse.error.code}): ${rpcResponse.error.message}`
          });
        }

        const result = rpcResponse.result ?? {};
        const capsule = result.capsule as DecisionCapsule;
        const admissibility = result.lifecycle_admissibility ?? {};

        const canAdvance = Boolean(admissibility.can_advance);
        const remediations = (admissibility.remediation_actions as string[]) ?? [];

        return resolve({
          admitted: canAdvance,
          stage,
          capsule,
          remediation_actions: remediations
        });
      } catch (parseError: unknown) {
        const message = parseError instanceof Error ? parseError.message : String(parseError);
        return resolve({
          admitted: false,
          stage,
          remediation_actions: ["Validar formato de respuesta JSON-RPC"],
          error: `Error parseando respuesta JSON de Refuto: ${message}`
        });
      }
    });

    proc.stdin.write(JSON.stringify(rpcRequest) + "\n");
    proc.stdin.end();
  });
}
