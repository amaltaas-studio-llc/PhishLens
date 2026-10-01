// The one constructor the evaluation runner uses. Declared here rather than by adding @types/jsdom, which
// would be a dependency for a single call.
declare module 'jsdom' {
  export class VirtualConsole {
    on(event: string, listener: (...args: unknown[]) => void): this;
  }
  export class JSDOM {
    constructor(html: string, options?: { virtualConsole?: VirtualConsole });
    readonly window: { readonly document: Document };
  }
}
