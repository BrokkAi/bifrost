import { RQL_LANGUAGE_ID } from "./rql_query";

export const VALIDATE_RQL_QUERY_METHOD = "bifrost/validateQuery";
export const RQL_QUERY_HOVER_METHOD = "bifrost/queryHover";
export const RQL_POLICY_LANGUAGE_ID = "bifrost-rql-policy";
export const VALIDATE_RQL_POLICY_METHOD = "bifrost/validatePolicy";
export const RQL_POLICY_HOVER_METHOD = "bifrost/policyHover";
export const RQL_VALIDATION_DELAY_MS = 300;
export const RQL_SOURCE_LANGUAGE_IDS = [RQL_LANGUAGE_ID, RQL_POLICY_LANGUAGE_ID] as const;

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
  validate(
    document: RqlValidationDocument,
    token: Token
  ): Promise<{ diagnostics: WireDiagnostic[] }>;
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
    if (!isRqlSourceLanguage(document.languageId)) {
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
      const response = await this.dependencies.validate(document, cancellation.token);
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

export function policyHoverParams(
  source: string,
  position: WirePosition
): { source: string; position: WirePosition } {
  return { source, position };
}

export function isRqlSourceLanguage(languageId: string): boolean {
  return RQL_SOURCE_LANGUAGE_IDS.some((candidate) => candidate === languageId);
}

/** Shared selectors for custom hover and standard LSP formatting/completion. */
export function rqlFileDocumentSelectors(): Array<{
  scheme: "file";
  language: (typeof RQL_SOURCE_LANGUAGE_IDS)[number];
}> {
  return RQL_SOURCE_LANGUAGE_IDS.map((language) => ({ scheme: "file", language }));
}

export type RqlValidationRequest =
  | { method: typeof VALIDATE_RQL_QUERY_METHOD; params: { query: string } }
  | { method: typeof VALIDATE_RQL_POLICY_METHOD; params: { source: string } };

export function validationRequest(
  document: RqlValidationDocument
): RqlValidationRequest | undefined {
  switch (document.languageId) {
    case RQL_LANGUAGE_ID:
      return {
        method: VALIDATE_RQL_QUERY_METHOD,
        params: { query: document.text }
      };
    case RQL_POLICY_LANGUAGE_ID:
      return {
        method: VALIDATE_RQL_POLICY_METHOD,
        params: { source: document.text }
      };
    default:
      return undefined;
  }
}

export type RqlHoverRequest =
  | {
      method: typeof RQL_QUERY_HOVER_METHOD;
      params: ReturnType<typeof queryHoverParams>;
    }
  | {
      method: typeof RQL_POLICY_HOVER_METHOD;
      params: ReturnType<typeof policyHoverParams>;
    };

export function hoverRequest(
  languageId: string,
  source: string,
  position: WirePosition
): RqlHoverRequest | undefined {
  switch (languageId) {
    case RQL_LANGUAGE_ID:
      return {
        method: RQL_QUERY_HOVER_METHOD,
        params: queryHoverParams(source, position)
      };
    case RQL_POLICY_LANGUAGE_ID:
      return {
        method: RQL_POLICY_HOVER_METHOD,
        params: policyHoverParams(source, position)
      };
    default:
      return undefined;
  }
}

/** Clear pending work and published diagnostics when the LSP connection dies. */
export function handleRqlServerClosed(
  controller: Pick<RqlValidationController<unknown>, "stop"> | undefined
): void {
  controller?.stop();
}
