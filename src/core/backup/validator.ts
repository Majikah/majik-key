import { MnemonicJSON } from "../types";
import { InvalidBackupJSONError } from "./error";

/**
 * Single source of truth for "is this a structurally valid
 * MnemonicJSON". Called by `create`, `fromJSON`, `fromPNG` (post-decode),
 * and `fromZIP` — never reimplemented at any entry point (DRY validation:
 * one validator, many callers).
 *
 * Throws InvalidBackupJSONError with a specific reason on failure;
 * narrows `input` to MnemonicJSON on success.
 */
export function validateMnemonicJSONShape(
  input: unknown,
): asserts input is MnemonicJSON {
  if (typeof input !== "object" || input === null) {
    throw new InvalidBackupJSONError("payload is not an object");
  }

  const candidate = input as Record<string, unknown>;

  if (typeof candidate.id !== "string" || !candidate.id.trim()) {
    throw new InvalidBackupJSONError("missing or empty `id`");
  }

  if (!Array.isArray(candidate.seed) || candidate.seed.length === 0) {
    throw new InvalidBackupJSONError("missing or empty `seed`");
  }

  if (
    !candidate.seed.every(
      (word) => typeof word === "string" && word.trim().length > 0,
    )
  ) {
    throw new InvalidBackupJSONError(
      "`seed` must be an array of non-empty words",
    );
  }

  if (candidate.phrase !== undefined && typeof candidate.phrase !== "string") {
    throw new InvalidBackupJSONError("`phrase` must be a string when present");
  }

  if (
    candidate.language !== undefined &&
    typeof candidate.language !== "string"
  ) {
    throw new InvalidBackupJSONError(
      "`language` must be a string when present",
    );
  }

  if (
    candidate.version !== undefined &&
    typeof candidate.version !== "number"
  ) {
    throw new InvalidBackupJSONError("`version` must be a number when present");
  }
}
