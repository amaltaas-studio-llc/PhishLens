// The part of jsdom the evaluation runner uses: a page and a console to silence it. Declared here rather
// than by adding @types/jsdom, which would be a dependency for two classes.
declare module 'jsdom' {
  export class VirtualConsole {
    on(event: string, listener: (...args: unknown[]) => void): this;
  }
  export class JSDOM {
    constructor(html: string, options?: { virtualConsole?: VirtualConsole });
    readonly window: { readonly document: Document };
  }
}
