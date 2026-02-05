/* -------------------------------
 * Errors
 * ------------------------------- */

export class MajikKeyError extends Error {
  cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "MajikKeyError";
    this.cause = cause;
  }
}
