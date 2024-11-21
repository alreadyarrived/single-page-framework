// @ts-check
/** @jsx React.createElement */
import React, { useState, useEffect, createContext, Suspense } from 'react';
import * as Y from 'yjs';
import { WebrtcProvider } from 'y-webrtc';
import { IndexeddbPersistence } from 'y-indexeddb';
import Gun from 'gun';
import { Workbox } from 'workbox-window';
import { createRoot } from 'react-dom/client';
import { Route, Router } from 'wouter';
import _sodium from 'libsodium-wrappers';
import { OAuth2Client } from 'google-auth-library';
import { defineConfig } from 'vite';

// Core Framework Configuration Types
interface FrameworkConfig {
  v: string;
  modes: ['dev', 'prod', 'test'];
  crypto: {
    keySize: number;
    saltLength: number;  // Length of salt to generate
  };
  auth: {
    providers: string[];
    clientId: string;
  };
  db: {
    collections: string[];
  };
  routes: {
    base: string;
    dynamic: boolean;
  };
}

// Define types for encryption
type EncryptableData = string | number | boolean | object | null;

// Core Framework Configuration
const CONFIG: FrameworkConfig = {
  v:'1.0.0',
  modes:['dev','prod','test'],
  crypto:{keySize:256, saltLength: 32},  // 32 bytes = 256 bits for salt
  auth:{providers:['google','github'],clientId:'YOUR_CLIENT_ID'},
  db:{collections:['users','data','sync']},
  routes:{base:'/',dynamic:true}
};

// Encryption Utilities
const Crypto={
  async init(){
    await _sodium.ready;
  },

  generateSalt(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(CONFIG.crypto.saltLength));
  },

  async deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: CONFIG.crypto.keySize },
      false,
      ['encrypt', 'decrypt']
    );
  },

  async aesEncrypt(data: EncryptableData, key: CryptoKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedData = new TextEncoder().encode(JSON.stringify(data));
    const cipherBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encodedData
    );
    return {
      c: this.arrayBufferToBase64(cipherBuffer),
      iv: this.arrayBufferToBase64(iv)
    };
  },
  async aesDecrypt(ciphertext: string, key: CryptoKey, iv: string) {
    const cipherBuffer = this.base64ToArrayBuffer(ciphertext);
    const ivBuffer = this.base64ToArrayBuffer(iv);
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBuffer },
      key,
      cipherBuffer
    );
    const decryptedText = new TextDecoder().decode(decryptedBuffer);
    return decryptedText;
  },

  arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
    const binary = bytes.reduce((str, byte) => str + String.fromCharCode(byte), '');
    return btoa(binary);
  },
  base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
};

// Advanced Routing Types
type RouteSegment = string | number | { [key: string]: string };
type MiddlewareFunction = (context: RouteContext) => Promise<boolean>;

interface RouteContext {
  params: { [key: string]: string };
  query: URLSearchParams;
  path: string;
  headers: Headers;
  body?: unknown;
  error?: Error;
}

interface RouteConfig {
  component: React.ComponentType<any>;
  layout?: React.ComponentType<any>;
  loading?: React.ComponentType;
  error?: React.ComponentType<{ error: Error }>;
  middleware?: MiddlewareFunction[];
  children?: Map<string, RouteConfig>;
}

// Define state management types
interface AppState {
  user?: {
    id: string;
    name: string;
    email: string;
  };
  theme: 'light' | 'dark';
  settings: Record<string, unknown>;
}

// Initial state
const initialState: AppState = {
  theme: 'light',
  settings: {}
};

// Define prop types for components
interface BaseProps {
  children?: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}

// Define Gun types
interface GunData {
  c: string;  // ciphertext
  iv: string; // initialization vector
}

interface GunChain {
  get(key: string): GunChain;
  put(data: GunData): Promise<void>;
  once(cb: (data: GunData) => void): void;
}

// Service Worker Setup
const SW = {
  async register() {
    if ('serviceWorker' in navigator) {
      const wb = new Workbox('/sw.js');
      await wb.register();
      return wb;
    }
  }
};

// Database Layer
class DB {
  private yDoc: Y.Doc;
  private persistence: IndexeddbPersistence;
  private provider: WebrtcProvider;
  private _key: CryptoKey | null = null;
  private gun: GunChain;
  private operationQueue: Promise<any> = Promise.resolve();
  private lockMap = new Map<string, Promise<void>>();

  constructor(){
    this.yDoc = new Y.Doc();
    this.persistence = new IndexeddbPersistence('framework-db', this.yDoc);
    this.gun = Gun() as unknown as GunChain;
    this.provider = new WebrtcProvider('framework-room', this.yDoc);
  }

  // Getter and setter for key with proper validation
  get key(): CryptoKey {
    if (!this._key) {
      throw new Error('CryptoKey not initialized. Call initializeKey() first.');
    }
    return this._key;
  }

  set key(value: CryptoKey) {
    this._key = value;
  }

  async initializeKey(): Promise<void> {
    if (!this._key) {
      // Generate a secure key using the Web Crypto API
      const keyMaterial = await window.crypto.subtle.generateKey(
        {
          name: 'AES-GCM',
          length: CONFIG.crypto.keySize
        },
        true,
        ['encrypt', 'decrypt']
      );
      this._key = keyMaterial;
    }
  }

  async get(k: string) {
    await this.initializeKey();
    return new Promise<any>((resolve) => {
      this.gun.get(k).once((data: GunData) => {
        if (!data) resolve(null);
        else resolve(Crypto.aesDecrypt(data.c, this.key!, data.iv));
      });
    });
  }

  async set(k: string, v: any) {
    // Ensure operations on same key are sequential
    const lock = this.lockMap.get(k) || Promise.resolve();
    const newLock = lock.then(async () => {
      try {
        await this.initializeKey();
        const encrypted = await Crypto.aesEncrypt(JSON.stringify(v), this.key!);
        await this.gun.get(k).put({ c: encrypted.c, iv: encrypted.iv });
      } finally {
        if (this.lockMap.get(k) === newLock) {
          this.lockMap.delete(k);
        }
      }
    });
    this.lockMap.set(k, newLock);
    return newLock;
  }

  async waitForSync() {
    await this.persistence.whenSynced;
  }
}

// Authentication Manager
interface TokenInfo {
  value: any;
  expiresAt: number;
}

class Auth {
  private oauth: OAuth2Client;
  private tokens: Map<string, TokenInfo>;
  private readonly MAX_TOKENS = 1000;  // Maximum number of tokens to store
  private readonly CLEANUP_INTERVAL = 5 * 60 * 1000;  // Cleanup every 5 minutes

  constructor() {
    this.oauth = new OAuth2Client();
    this.tokens = new Map();
    
    // Start the cleanup interval
    setInterval(() => this.cleanupExpiredTokens(), this.CLEANUP_INTERVAL);
  }

  private cleanupExpiredTokens() {
    const now = Date.now();
    for (const [key, tokenInfo] of this.tokens.entries()) {
      if (tokenInfo.expiresAt <= now) {
        this.tokens.delete(key);
      }
    }
  }

  setToken(key: string, value: any, expirationMinutes: number = 60) {
    // Remove oldest token if we hit the size limit
    if (this.tokens.size >= this.MAX_TOKENS) {
      const iterator = this.tokens.keys();
      const next = iterator.next();
      if (!next.done) {
        this.tokens.delete(next.value);
      }
    }

    const expiresAt = Date.now() + (expirationMinutes * 60 * 1000);
    this.tokens.set(key, { value, expiresAt });
  }

  getToken(key: string): any | null {
    const tokenInfo = this.tokens.get(key);
    if (!tokenInfo) return null;

    const now = Date.now();
    if (tokenInfo.expiresAt <= now) {
      this.tokens.delete(key);
      return null;
    }

    return tokenInfo.value;
  }

  async login(p: string): Promise<any> {
    const t = await this.oauth.getToken(p);
    this.setToken(p, t);
    return t;
  }

  async verify(t: string): Promise<boolean> {
    try {
      const ticket = await this.oauth.verifyIdToken({
        idToken: t,
        audience: CONFIG.auth.clientId
      });
      const payload = ticket.getPayload();
      return !!payload;
    } catch (error) {
      console.error('Token verification failed:', error);
      return false;
    }
  }
}

// Router Implementation
const AppRouter = {
  routes: new Map<string, RouteConfig>(),
  
  // Add a route with full configuration
  add(path: string, config: RouteConfig | React.ComponentType) {
    if (typeof config === 'function') {
      this.routes.set(path, { component: config });
    } else {
      this.routes.set(path, config);
    }
  },

  // Add middleware to a route
  addMiddleware(path: string, ...middleware: MiddlewareFunction[]) {
    const route = this.routes.get(path);
    if (route) {
      route.middleware = [...(route.middleware || []), ...middleware];
    }
  },

  // Parse dynamic route parameters
  parseParams(pattern: string, path: string): { [key: string]: string } | null {
    const patternParts = pattern.split('/');
    const pathParts = path.split('/');
    
    if (patternParts.length !== pathParts.length && !pattern.includes('[...')) {
      return null;
    }

    const params: { [key: string]: string } = {};
    
    for (let i = 0; i < patternParts.length; i++) {
      const patternPart = patternParts[i];
      const pathPart = pathParts[i];
      
      if (patternPart.startsWith('[...') && patternPart.endsWith(']')) {
        // Catch-all route
        const paramName = patternPart.slice(4, -1);
        params[paramName] = pathParts.slice(i).join('/');
        break;
      } else if (patternPart.startsWith('[') && patternPart.endsWith(']')) {
        // Dynamic parameter
        const paramName = patternPart.slice(1, -1);
        params[paramName] = pathPart;
      } else if (patternPart !== pathPart) {
        return null;
      }
    }
    
    return params;
  },

  // Resolve a path to its component and context
  async resolve(path: string): Promise<{
    component: React.ComponentType<any>;
    context: RouteContext;
    layout?: React.ComponentType<any>;
    loading?: React.ComponentType;
    error?: React.ComponentType<{ error: Error }>;
  } | null> {
    const url = new URL(path, window.location.origin);
    let matchedRoute: [string, RouteConfig] | undefined;

    // Find matching route including dynamic routes
    for (const [pattern, config] of this.routes) {
      const params = this.parseParams(pattern, url.pathname);
      if (params) {
        matchedRoute = [pattern, config];
        const context: RouteContext = {
          params,
          query: url.searchParams,
          path: url.pathname,
          headers: new Headers(),
          body: undefined,
          error: undefined,
        };

        // Run middleware
        if (config.middleware) {
          try {
            for (const middleware of config.middleware) {
              const shouldContinue = await middleware(context);
              if (!shouldContinue) {
                return null;
              }
            }
          } catch (error) {
            if (config.error) {
              return {
                component: config.error,
                context: { ...context, error: error as Error },
                layout: config.layout
              };
            }
            throw error;
          }
        }

        return {
          component: config.component,
          context,
          layout: config.layout,
          loading: config.loading,
          error: config.error
        };
      }
    }

    return null;
  }
};

// Testing Framework
interface TestInterface {
  cases: Map<any, any>;
  add(n: string, f: () => void): void;
  run(): Promise<void>;
}

const Test: TestInterface = {
  cases: new Map(),
  add(n: string, f: () => void) { this.cases.set(n, f) },
  async run() {
    for (const [n, f] of this.cases) {
      try { await f(); console.log(`✓ ${n}`) } catch (e) { console.error(`✗ ${n}:`, e) }
    }
  }
};

// Plugin System
const Plugins = {
  registry: new Map(),
  register(n: string, p: any) { this.registry.set(n, p) },
  get(n: string) { return this.registry.get(n) },
};

// Network Manager for Offline Support and Resilience
class NetworkManager {
  private static instance: NetworkManager;
  private onlineSubscribers: Set<(online: boolean) => void> = new Set();
  private retryQueue: Map<string, (() => Promise<void>)[]> = new Map();
  private networkStatus: boolean = navigator.onLine;

  private constructor() {
    window.addEventListener('online', () => this.handleNetworkChange(true));
    window.addEventListener('offline', () => this.handleNetworkChange(false));
  }

  static getInstance(): NetworkManager {
    if (!NetworkManager.instance) {
      NetworkManager.instance = new NetworkManager();
    }
    return NetworkManager.instance;
  }

  private async handleNetworkChange(online: boolean) {
    this.networkStatus = online;
    this.notifySubscribers(online);
    
    if (online) {
      await this.processRetryQueue();
    }
  }

  private notifySubscribers(online: boolean) {
    this.onlineSubscribers.forEach(subscriber => subscriber(online));
  }

  subscribeToNetworkChanges(callback: (online: boolean) => void) {
    this.onlineSubscribers.add(callback);
    return () => this.onlineSubscribers.delete(callback);
  }

  private async processRetryQueue() {
    for (const [key, operations] of this.retryQueue) {
      for (const operation of operations) {
        try {
          await operation();
        } catch (error) {
          console.error(`Failed to process operation ${key}:`, error);
        }
      }
      this.retryQueue.delete(key);
    }
  }

  async executeWithRetry<T>(
    key: string,
    operation: () => Promise<T>,
    maxRetries: number = 3
  ): Promise<T> {
    if (!this.networkStatus) {
      const operations = this.retryQueue.get(key) || [];
      operations.push(operation as () => Promise<void>);
      this.retryQueue.set(key, operations);
      throw new Error('Operation queued for retry when online');
    }

    let lastError: Error | undefined;
    for (let i = 0; i < maxRetries; i++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error as Error;
        await new Promise(resolve => setTimeout(resolve, Math.pow(2, i) * 1000));
      }
    }
    throw lastError;
  }

  isOnline(): boolean {
    return this.networkStatus;
  }
}

// Service Provider Interface and Container
interface ServiceProvider {
  get<T>(token: symbol): T;
  register<T>(token: symbol, implementation: T): void;
}

class Container implements ServiceProvider {
  private services = new Map<symbol, any>();

  get<T>(token: symbol): T {
    if (!this.services.has(token)) {
      throw new Error(`Service ${token.toString()} not registered`);
    }
    return this.services.get(token);
  }

  register<T>(token: symbol, implementation: T): void {
    this.services.set(token, implementation);
  }
}

// Service Tokens
const SERVICE_TOKENS = {
  DB: Symbol('DB'),
  AUTH: Symbol('Auth'),
  ROUTER: Symbol('Router'),
  NETWORK: Symbol('Network'),
  CRYPTO: Symbol('Crypto'),
  TEST: Symbol('Test'),
  PLUGINS: Symbol('Plugins'),
  SECURITY: Symbol('Security'),
};

// Base Service Interface
interface Service {
  init?(): Promise<void>;
  dispose?(): Promise<void>;
}

// Database Service
class DatabaseService implements Service {
  private readonly db: DB;
  
  constructor() {
    this.db = new DB();
  }

  async init() {
    await this.db.waitForSync();
  }

  async dispose() {
    // Cleanup database connections
  }

  get instance() {
    return this.db;
  }
}

// Auth Service
class AuthService implements Service {
  private readonly auth: Auth;
  
  constructor() {
    this.auth = new Auth();
  }

  async init() {
    // Initialize auth service
  }

  async dispose() {
    // Cleanup auth resources
  }

  get instance() {
    return this.auth;
  }
}

// Router Service
class RouterService implements Service {
  private readonly router: typeof AppRouter;
  
  constructor() {
    this.router = AppRouter;
  }

  async init() {
    // Initialize router
  }

  async dispose() {
    // Cleanup router resources
  }

  get instance() {
    return this.router;
  }
}

// Network Service
class NetworkService implements Service {
  private readonly network: NetworkManager;
  
  constructor() {
    this.network = NetworkManager.getInstance();
  }

  async init() {
    // Initialize network service
  }

  async dispose() {
    // Cleanup network resources
  }

  get instance() {
    return this.network;
  }
}

// Security Service
class SecurityService implements Service {
  private static instance: SecurityService;
  private readonly rateLimiter = new Map<string, { 
    count: number;
    resetAt: number;
  }>();
  private readonly csrfTokens = new Map<string, { 
    token: string; 
    expires: number;
  }>();
  
  private static readonly TOKEN_EXPIRY = 3600000; // 1 hour
  private static readonly CLEANUP_INTERVAL = 300000; // 5 minutes
  private static readonly DEFAULT_RATE_LIMIT = 100;
  private static readonly DEFAULT_WINDOW_MS = 60000; // 1 minute
  
  private cleanupTimer?: number;
  
  private constructor() {
    this.startCleanupTimer();
  }

  private startCleanupTimer() {
    try {
      this.cleanupTimer = window.setInterval(() => {
        this.cleanup();
      }, SecurityService.CLEANUP_INTERVAL);
    } catch (error) {
      console.error('Failed to start cleanup timer:', error);
    }
  }

  static getInstance(): SecurityService {
    if (!SecurityService.instance) {
      SecurityService.instance = new SecurityService();
    }
    return SecurityService.instance;
  }

  async init(): Promise<void> {
    // Initialize service
    this.cleanup();
  }

  async dispose(): Promise<void> {
    if (this.cleanupTimer !== undefined) {
      window.clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
    this.rateLimiter.clear();
    this.csrfTokens.clear();
  }

  private cleanup(): void {
    try {
      const now = Date.now();
      
      // Cleanup CSRF tokens
      for (const [sessionId, data] of this.csrfTokens) {
        if (data.expires <= now) {
          this.csrfTokens.delete(sessionId);
        }
      }
      
      // Cleanup rate limiter
      for (const [key, data] of this.rateLimiter) {
        if (data.resetAt <= now) {
          this.rateLimiter.delete(key);
        }
      }
    } catch (error) {
      console.error('Error during cleanup:', error);
    }
  }

  generateCSRFToken(sessionId: string): string {
    try {
      const token = crypto.randomUUID();
      this.csrfTokens.set(sessionId, {
        token,
        expires: Date.now() + SecurityService.TOKEN_EXPIRY
      });
      return token;
    } catch (error) {
      console.error('Failed to generate CSRF token:', error);
      throw new Error('Failed to generate security token');
    }
  }

  validateCSRFToken(sessionId: string, token: string): boolean {
    try {
      const storedData = this.csrfTokens.get(sessionId);
      if (!storedData) return false;
      
      if (Date.now() > storedData.expires) {
        this.csrfTokens.delete(sessionId);
        return false;
      }
      
      return storedData.token === token;
    } catch (error) {
      console.error('Error validating CSRF token:', error);
      return false;
    }
  }

  isRateLimited(key: string, limit: number = SecurityService.DEFAULT_RATE_LIMIT, 
                windowMs: number = SecurityService.DEFAULT_WINDOW_MS): boolean {
    try {
      const now = Date.now();
      const data = this.rateLimiter.get(key);
      
      if (!data || data.resetAt <= now) {
        this.rateLimiter.set(key, {
          count: 1,
          resetAt: now + windowMs
        });
        return false;
      }
      
      if (data.count >= limit) {
        return true;
      }
      
      data.count++;
      return false;
    } catch (error) {
      console.error('Error checking rate limit:', error);
      return true; // Fail safe: rate limit on error
    }
  }

  sanitizeInput(input: string | null | undefined): string {
    if (input == null) return '';
    
    try {
      return input.replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
      }[char] || char));
    } catch (error) {
      console.error('Error sanitizing input:', error);
      return ''; // Return empty string on error
    }
  }

  createSecurityMiddleware(options: {
    csrf?: boolean;
    rateLimit?: { 
      limit?: number; 
      windowMs?: number; 
    };
    sanitize?: boolean;
  } = {}): MiddlewareFunction {
    
    return async (context: RouteContext): Promise<boolean> => {
      try {
        const sessionId = context.headers.get('X-Session-ID');
        if (!sessionId) {
          throw new Error('Session ID required');
        }

        // CSRF Protection
        if (options.csrf) {
          const token = context.headers.get('X-CSRF-Token');
          if (!token || !this.validateCSRFToken(sessionId, token)) {
            throw new Error('Invalid or missing CSRF token');
          }
        }

        // Rate Limiting
        if (options.rateLimit) {
          const { limit = SecurityService.DEFAULT_RATE_LIMIT, 
                  windowMs = SecurityService.DEFAULT_WINDOW_MS } = options.rateLimit;
          
          if (this.isRateLimited(sessionId, limit, windowMs)) {
            throw new Error('Rate limit exceeded');
          }
        }

        // Input Sanitization
        if (options.sanitize && context.body !== undefined) {
          if (typeof context.body === 'string') {
            context.body = this.sanitizeInput(context.body);
          } else if (typeof context.body === 'object') {
            context.body = JSON.parse(
              this.sanitizeInput(JSON.stringify(context.body))
            );
          }
        }

        return true; // Successfully passed all security checks
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Security check failed';
        throw new Error(`Security Error: ${message}`);
      }
    };
  }
}

// Core Framework
class CoreFramework {
  protected readonly container: Container;
  protected readonly config: FrameworkConfig;

  constructor(config: FrameworkConfig = CONFIG) {
    this.config = config;
    this.container = new Container();
    
    // Register core services
    this.container.register(SERVICE_TOKENS.DB, new DatabaseService());
    this.container.register(SERVICE_TOKENS.AUTH, new AuthService());
    this.container.register(SERVICE_TOKENS.ROUTER, new RouterService());
    this.container.register(SERVICE_TOKENS.NETWORK, new NetworkService());
    this.container.register(SERVICE_TOKENS.CRYPTO, Crypto);
    this.container.register(SERVICE_TOKENS.TEST, Test);
    this.container.register(SERVICE_TOKENS.PLUGINS, Plugins);
    this.container.register(SERVICE_TOKENS.SECURITY, SecurityService.getInstance());
  }

  getService<T>(token: symbol): T {
    return this.container.get<T>(token);
  }

  async init() {
    const crypto = this.getService<typeof Crypto>(SERVICE_TOKENS.CRYPTO);
    const db = this.getService<DatabaseService>(SERVICE_TOKENS.DB);
    
    await crypto.init();
    await SW.register();
    await db.init?.();
  }

  get db() {
    return this.getService<DatabaseService>(SERVICE_TOKENS.DB).instance;
  }

  get auth() {
    return this.getService<AuthService>(SERVICE_TOKENS.AUTH).instance;
  }

  get router() {
    return this.getService<RouterService>(SERVICE_TOKENS.ROUTER).instance;
  }

  get network() {
    return this.getService<NetworkService>(SERVICE_TOKENS.NETWORK).instance;
  }

  get test() {
    return this.getService<typeof Test>(SERVICE_TOKENS.TEST);
  }

  get plugins() {
    return this.getService<typeof Plugins>(SERVICE_TOKENS.PLUGINS);
  }

  get security() {
    return this.getService<SecurityService>(SERVICE_TOKENS.SECURITY);
  }
}

// Main Framework Implementation
class FrameworkImpl extends CoreFramework {
  constructor(config: FrameworkConfig = CONFIG) {
    super(config);
  }

  private readonly _testFramework: TestInterface = this.getService<typeof Test>(SERVICE_TOKENS.TEST);

  override get test() {
    return this._testFramework;
  }

  // Test Registration
  registerTest(n: string, f: () => void) { 
    this._testFramework.add(n, f);
  }

  async init(){
    await Crypto.init();
    await SW.register();
    await this.db.waitForSync();
  }

  // Enhanced route registration with full configuration
  route(path: string, config: RouteConfig | React.ComponentType) {
    if (typeof config === 'function') {
      this.router.add(path, { component: config });
    } else {
      this.router.add(path, config);
    }
    return this;
  }

  // Add route middleware
  routeMiddleware(path: string, ...middleware: MiddlewareFunction[]) {
    this.router.addMiddleware(path, ...middleware);
    return this;
  }

  // Create a route group with shared layout
  routeGroup(layout: React.ComponentType) {
    return (path: string, component: React.ComponentType) => {
      this.route(path, { component, layout });
      return this;
    };
  }

  // Component Factory with proper typing
  component<P extends BaseProps>(Component: React.ComponentType<P>, props: P = {} as P): React.ReactElement {
    return React.createElement(Component, props);
  }

  // Plugin Registration
  use(p: any) { 
    this.plugins.register(p.name, p);
    return this;
  }

  // Application Bootstrap
  start(el: HTMLElement) {
    const AppComponent = this.App();
    this.init();
    createRoot(el).render(<AppComponent />);
  }

  // Override the App component to support layouts
  App(): React.ComponentType {
    return () => {
      const [state, setState] = useState<AppState>(initialState);
      const [loading, setLoading] = useState(true);
      const [error, setError] = useState<Error | null>(null);
      const [routeComponent, setRouteComponent] = useState<React.ReactElement | null>(null);
      
      const setPartialState = (update: Partial<AppState>) => {
        setState(current => ({...current, ...update}));
      };

      const value: AppContextType = {
        config: this.config,
        db: this.db,
        auth: this.auth,
        router: AppRouter,
        test: this.test,
        plugins: this.plugins,
        framework: this,
        state,
        setState: setPartialState,
        network: this.network,
        security: this.security,
      };

      useEffect(() => {
        const loadRoute = async () => {
          try {
            setLoading(true);
            const path = window.location.pathname;
            const resolved = await AppRouter.resolve(path);
            
            if (resolved) {
              const RouteComponent = resolved.component;
              setRouteComponent(
                <RouteComponent 
                  context={resolved.context}
                  {...value}
                />
              );
            } else if (loading) {
              setRouteComponent(null);
            }

            if (error) {
              const ErrorComponent = resolved?.error;
              setRouteComponent(
                ErrorComponent ? <ErrorComponent error={error} /> : null
              );
            }

          } catch (err) {
            setError(err as Error);
            setRouteComponent(null);
          } finally {
            setLoading(false);
          }
        };

        loadRoute();
      }, [window.location.pathname]);

      if (loading && !error) {
        return <div>Loading...</div>;
      }

      return routeComponent || <div>404 Not Found</div>;
    };
  }
}

// Framework Context
const FrameworkContext = createContext<CoreFramework | null>(null);

export function useFramework() {
  const framework = React.useContext(FrameworkContext);
  if (!framework) {
    throw new Error('useFramework must be used within a FrameworkProvider');
  }
  return framework;
}

// Framework Provider Component
export function FrameworkProvider({ 
  config = CONFIG,
  children 
}: { 
  config?: FrameworkConfig;
  children: React.ReactNode;
}) {
  const [framework] = useState(() => new CoreFramework(config));

  return (
    <FrameworkContext.Provider value={framework}>
      {children}
    </FrameworkContext.Provider>
  );
}

// Define the type for our application context
interface AppContextType {
  config: FrameworkConfig;
  db: DB;
  auth: Auth;
  router: typeof AppRouter;
  test: TestInterface;
  plugins: typeof Plugins;
  framework: CoreFramework;
  state: AppState;
  setState: (state: Partial<AppState>) => void;
  network: NetworkManager;
  security: SecurityService;
}

// CI/CD Configuration
const ciConfig = `
name: CI/CD
on: [push]
jobs:
  build-test-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
      - run: npm ci
      - run: npm test
      - run: npm run build
      - uses: actions/deploy-pages@v1
`;

// Vite Configuration
const viteConfig = defineConfig({
  plugins: [],
  build: {
    minify: 'esbuild',
    target: 'esnext',
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'yjs', 'gun'],
          framework: ['./framework.js']
        }
      }
    }
  }
});

// Export Framework Instance
export default new FrameworkImpl();