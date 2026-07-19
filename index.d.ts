/// <reference types="node" />

declare module 'fortifyjs' {
  export type Tier = 'basic' | 'medium' | 'hard' | 'advanced';

  export type DetectionLabel = 'sqli' | 'xss' | 'nosqli' | 'cmdi' | 'path-traversal' | 'ssrf' | 'xxe' | 'prototype-pollution' | 'hpp' | 'open-redirect' | 'crlf' | 'templateInjection' | 'ldap' | 'graphql' | 'benign' | 'anomaly' | string;
  export type DetectorType = 'sqli' | 'xss' | 'nosqli' | 'cmdi' | 'path-traversal' | 'ssrf' | 'xxe' | 'prototype-pollution' | 'hpp' | 'open-redirect' | 'crlf' | 'templateInjection' | 'ldap' | 'graphql' | string;

  export interface RateLimitOptions {
    max?: number;
    windowMs?: number;
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
    dashboard?: boolean | { enabled?: boolean; path?: string };
    whitelist?: WhitelistOptions;
    mode?: 'input' | 'query';
    logging?: { level?: 'silent' | 'error' | 'warn' | 'info' | 'debug'; format?: 'json' | 'text' };
  }

  export type ShieldOptions = FortifyOptions;

  export function shield(tier?: Tier, overrides?: FortifyOptions): (req: any, res: any, next: any) => void;
  export function shield(overrides?: FortifyOptions): (req: any, res: any, next: any) => void;

  export function fastifyPlugin(fastify: any, options: FortifyOptions, done: () => void): void;
  export function koaMiddleware(options?: FortifyOptions): (ctx: any, next: () => Promise<any>) => Promise<void>;
  export function honoMiddleware(options?: FortifyOptions): (c: any, next: () => Promise<any>) => Promise<void>;
  export function genericAdapter(options?: FortifyOptions): (req: any, res: any, next: any) => void;

  export class DetectionEngine {
    constructor(options?: any);
    detect(payload: string, context?: { source?: 'query' | 'body' | 'header' | 'cookie' | 'path' | 'filename' | string; route?: string; [key: string]: any }): any;
  }

  export class Normalizer {
    constructor(options?: any);
    normalizePayload(payload: string | Buffer, options?: any): string;
  }
}
