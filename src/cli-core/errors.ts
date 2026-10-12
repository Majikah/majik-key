/**
 * src/cli-core/errors.ts
 *
 * Error types for the Majik Key CLI. Operations throw; the command wrapper in
 * src/cli.ts is the only place that turns an error into output + exit code.
 *
 * Exit codes:
 *   0   success
 *   1   operation failed (wrong passphrase, bad file, ...)
 *   2   usage error (bad flag combination, invalid value)
 *   130 cancelled by the user (Ctrl-C at a prompt)
 */

export class CliError extends Error {
  readonly exitCode: number;

  constructor(message: string, exitCode = 1) {
    super(message);
    this.name = "CliError";
    this.exitCode = exitCode;
  }
}

export class UsageError extends CliError {
  constructor(message: string) {
    super(message, 2);
    this.name = "UsageError";
  }
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
