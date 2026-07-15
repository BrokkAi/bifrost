import { RQL_LANGUAGE_ID } from "./rql_query";

export const VALIDATE_RQL_QUERY_METHOD = "bifrost/validateQuery";
export const RQL_QUERY_HOVER_METHOD = "bifrost/queryHover";
export const RQL_VALIDATION_DELAY_MS = 300;

export interface WirePosition {
  line: number;
  character: number;
}

export interface WireRange {
  start: WirePosition;
  end: WirePosition;
}

export interface WireDiagnostic {
  range: WireRange;
  severity?: number;
  code?: string | number;
  source?: string;
  message: string;
}

export interface WireHover {
  contents: { kind: string; value: string };
  range?: WireRange;
}

export interface RqlValidationDocument {
  uri: string;
  languageId: string;
  version: number;
  text: string;
}

export interface CancellationSource<Token = unknown> {
  token: Token;
  cancel(): void;
  dispose(): void;
}

export interface RqlValidationDependencies<Token = unknown> {
  validate(query: string, token: Token): Promise<{ diagnostics: WireDiagnostic[] }>;
  publish(uri: string, diagnostics: WireDiagnostic[]): void;
  clear(uri: string): void;
  isCurrent(document: RqlValidationDocument): boolean;
  createCancellationSource(): CancellationSource<Token>;
  setTimer(callback: () => void, delayMs: number): unknown;
  clearTimer(timer: unknown): void;
}

interface ValidationState<Token> {
  generation: number;
  timer?: unknown;
  cancellation?: CancellationSource<Token>;
}

/** Owns debounce, cancellation, and stale-response rejection without a VS Code dependency. */
export class RqlValidationController<Token = unknown> {
  private readonly states = new Map<string, ValidationState<Token>>();

  constructor(
    private readonly dependencies: RqlValidationDependencies<Token>,
    private readonly delayMs = RQL_VALIDATION_DELAY_MS
  ) {}

  schedule(document: RqlValidationDocument): void {
    if (document.languageId !== RQL_LANGUAGE_ID) {
      this.close(document.uri);
      return;
    }

    const previous = this.states.get(document.uri);
    const generation = (previous?.generation ?? 0) + 1;
    this.cancelState(previous);
    const state: ValidationState<Token> = { generation };
    this.states.set(document.uri, state);
    state.timer = this.dependencies.setTimer(() => {
      state.timer = undefined;
      void this.run(document, generation);
    }, this.delayMs);
  }

  close(uri: string): void {
    this.cancelState(this.states.get(uri));
    this.states.delete(uri);
    this.dependencies.clear(uri);
  }

  stop(): void {
    for (const [uri, state] of this.states) {
      this.cancelState(state);
      this.dependencies.clear(uri);
    }
    this.states.clear();
  }

  private async run(document: RqlValidationDocument, generation: number): Promise<void> {
    const state = this.states.get(document.uri);
    if (!state || state.generation !== generation) {
      return;
    }
    const cancellation = this.dependencies.createCancellationSource();
    state.cancellation = cancellation;
    try {
      const response = await this.dependencies.validate(document.text, cancellation.token);
      const current = this.states.get(document.uri);
      if (current?.generation === generation && this.dependencies.isCurrent(document)) {
        this.dependencies.publish(document.uri, response.diagnostics);
      }
    } catch {
      // Background validation failures, including cancellation and server
      // lifecycle races, are intentionally silent.
    } finally {
      cancellation.dispose();
      const current = this.states.get(document.uri);
      if (current?.generation === generation) {
        current.cancellation = undefined;
      }
    }
  }

  private cancelState(state: ValidationState<Token> | undefined): void {
    if (state?.timer !== undefined) {
      this.dependencies.clearTimer(state.timer);
    }
    state?.cancellation?.cancel();
    state?.cancellation?.dispose();
  }
}

export function validationDocument(document: {
  uri: { toString(): string };
  languageId: string;
  version: number;
  getText(): string;
}): RqlValidationDocument {
  return {
    uri: document.uri.toString(),
    languageId: document.languageId,
    version: document.version,
    text: document.getText()
  };
}

export function queryHoverParams(
  query: string,
  position: WirePosition
): { query: string; position: WirePosition } {
  return { query, position };
}

/** Clear pending work and published diagnostics when the LSP connection dies. */
export function handleRqlServerClosed(
  controller: Pick<RqlValidationController<unknown>, "stop"> | undefined
): void {
  controller?.stop();
}
