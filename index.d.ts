/// <reference types="node" />

declare module 'fortifyjs' {
  export type Tier = 'basic' | 'medium' | 'hard' | 'advanced';

  export type DetectionLabel =
    | 'sqli'
    | 'xss'
    | 'nosqli'
    | 'cmdi'
    | 'path-traversal'
    | 'ssrf'
    | 'xxe'
    | 'prototype-pollution'
    | 'hpp'
    | 'open-redirect'
    | 'crlf'
    | 'template-injection'
    | 'ldap'
    | 'graphql'
    | 'prompt-injection'
    | 'benign'
    | 'anomaly'
    | string;

  export type DetectorType = DetectionLabel;

  export interface RateLimitOptions {
    max?: number;
    windowMs?: number;
    store?: BaseStore;
    keyGenerator?: (req: any) => string;
    standardHeaders?: boolean;
    handler?: (req: any, res: any, next: any, options: any) => void;
  }

  export interface CorsOptions {
    origin?: string | string[] | RegExp | ((origin: string, cb: (err: Error | null, allow?: boolean) => void) => void);
    methods?: string | string[];
    allowedHeaders?: string | string[];
    exposedHeaders?: string | string[];
    credentials?: boolean;
    maxAge?: number;
    optionsSuccessStatus?: number;
  }

  export interface CsrfOptions {
    cookieName?: string;
    cookieOptions?: {
      httpOnly?: boolean;
      secure?: boolean;
      sameSite?: boolean | 'lax' | 'strict' | 'none';
      path?: string;
    };
    ignoreMethods?: string[];
    secret?: string;
    silent?: boolean;
  }

  export interface BotDetectionOptions {
    enabled?: boolean;
    action?: 'flag' | 'block';
    blockList?: string[];
  }

  export interface BehavioralOptions {
    enabled?: boolean;
    entropyOnly?: boolean;
    learningRequests?: number;
  }

  export interface FileUploadOptions {
    enabled?: boolean;
    allowedExtensions?: string[];
    blockedExtensions?: string[];
    maxFilenameLength?: number;
    blockDoubleExtensions?: boolean;
    blockNullBytes?: boolean;
    blockPathTraversal?: boolean;
    blockDotFiles?: boolean;
    validateMimeType?: boolean;
    scanFilenameForInjection?: boolean;
  }

  export interface WhitelistOptions {
    exact?: string[];
    prefix?: string[];
    pattern?: RegExp[];
  }

  export interface SanitizerOptions {
    stripFields?: string[];
    rejectOnForbidden?: boolean;
  }

  export interface LlmGuardOptions {
    threshold?: number;
    fields?: string[];
    dryRun?: boolean;
    aiJudge?: ((promptText: string) => Promise<{ safe: boolean; reason?: string }>) | {
      provider?: 'openai' | 'ollama' | 'gemini';
      apiKey?: string;
      endpoint?: string;
      model?: string;
      fallback?: 'allow' | 'block';
    };
    onThreat?: (event: any, req: any, res: any) => void;
    onBlocked?: (req: any, res: any, event: any) => void;
  }

  export interface PromptScanResult {
    label: 'prompt-injection' | 'benign';
    confidence: number;
    safe: boolean;
    matches: Array<{ id: string; label: string; confidence: number }>;
    scores: Record<string, number>;
  }

  export interface FortifyOptions {
    tier?: Tier;
    level?: 'strict' | 'balanced' | 'permissive';
    headers?: boolean | Record<string, boolean | string>;
    rateLimit?: boolean | RateLimitOptions;
    cors?: boolean | CorsOptions;
    csrf?: boolean | CsrfOptions;
    botDetection?: boolean | BotDetectionOptions;
    behavioral?: boolean | BehavioralOptions;
    fileUpload?: boolean | FileUploadOptions;
    sanitize?: boolean | SanitizerOptions;
    dashboard?: boolean | { enabled?: boolean; path?: string };
    whitelist?: WhitelistOptions;
    mode?: 'input' | 'query';
    onBlocked?: (req: any, res: any, threat: any) => void;
    logging?: { level?: 'silent' | 'error' | 'warn' | 'info' | 'debug'; format?: 'json' | 'text' };
  }

  export type ShieldOptions = FortifyOptions;

  export function shield(tier?: Tier, overrides?: FortifyOptions): (req: any, res: any, next: any) => void;
  export function shield(overrides?: FortifyOptions): (req: any, res: any, next: any) => void;

  export function fastifyPlugin(fastify: any, options: FortifyOptions, done: () => void): void;
  export function koaMiddleware(options?: FortifyOptions): (ctx: any, next: () => Promise<any>) => Promise<void>;
  export function honoMiddleware(options?: FortifyOptions): (c: any, next: () => Promise<any>) => Promise<void>;
  export function genericAdapter(options?: FortifyOptions): (req: any, res: any, next: any) => void;

  // Runtime Sink Guardrails
  export function assertSafeSqlQuery(query: string, options?: any): any;
  export function scanSqlQuery(query: string, options?: any): any;
  export function assertSafeCommand(command: string, options?: any): any;
  export function assertSafePath(userPath: string, options?: { rootDir?: string; threshold?: number }): string;
  export function assertSafeUrl(targetUrl: string, options?: { allowPrivate?: boolean; allowedProtocols?: string[] }): URL;
  export function assertSafeNoSql(query: any, options?: { forbiddenOperators?: string[]; disallowAllOperators?: boolean }): any;
  export function assertSafeRedirect(destination: string, options?: { allowedHosts?: string[]; allowRelative?: boolean }): string;
  export function assertSafePrompt(prompt: string | any, options?: LlmGuardOptions): PromptScanResult;
  export function scanPrompt(prompt: string | any, options?: LlmGuardOptions): PromptScanResult;
  export function llmGuard(options?: LlmGuardOptions): (req: any, res: any, next: any) => void;

  // Sanitizer
  export function sanitizerFactory(options?: SanitizerOptions): (req: any, res: any, next: any) => void;
  export function sanitizeObject(obj: any, options?: SanitizerOptions): { sanitized: any; strippedKeys: string[]; wasForbidden: boolean };

  // Storage
  export class BaseStore {
    get(key: string): Promise<any>;
    set(key: string, value: any, ttlMs?: number): Promise<boolean>;
    increment(key: string, ttlMs?: number): Promise<{ count: number; resetTime: number }>;
    delete(key: string): Promise<boolean>;
    clear(): Promise<void>;
  }

  export class MemoryStore extends BaseStore {
    constructor(options?: { maxEntries?: number; cleanupIntervalMs?: number });
    destroy(): void;
  }

  export class DetectionEngine {
    constructor(options?: any);
    detect(payload: string, context?: { source?: 'query' | 'body' | 'header' | 'cookie' | 'path' | 'filename' | string; route?: string; [key: string]: any }): any;
  }

  export class Normalizer {
    constructor(options?: any);
    static normalizePayload(payload: string | Buffer, options?: any): string;
    static payloadVariants(payload: string | Buffer, options?: any): string[];
  }

  export class FortifySinkError extends Error {
    sinkType: string;
    status: number;
    code: string;
    result?: any;
  }

  export class FortifyPromptError extends Error {
    status: number;
    code: string;
    result: any;
    promptPreview: string;
  }
}
