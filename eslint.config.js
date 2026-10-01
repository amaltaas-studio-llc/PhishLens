// @ts-check
import tseslint from 'typescript-eslint';

/*
 * Restriction lists are built from these constants because flat config replaces a rule's options rather
 * than merging them: an override that adds one restricted global without restating the rest silently
 * lifts every ban it did not repeat. Each override below spreads the lists it inherits.
 */
const HOSTILE = 'Email content is hostile input. Use textContent / el() from src/ui/dom.ts.';

const HTML_SINK_PROPERTIES = [
  { property: 'innerHTML', message: HOSTILE },
  { property: 'outerHTML', message: HOSTILE },
  { property: 'insertAdjacentHTML', message: HOSTILE },
  { property: 'createContextualFragment', message: HOSTILE },
  { property: 'setHTMLUnsafe', message: HOSTILE },
  { object: 'document', property: 'write', message: HOSTILE },
  { object: 'document', property: 'writeln', message: HOSTILE },
];

const BASE_GLOBALS = [
  { name: 'Function', message: 'Never construct functions from extracted email content.' },
  { name: 'DOMParser', message: HOSTILE },
];

const FETCH_GLOBAL = {
  name: 'fetch',
  message: 'All egress is in src/background/index.ts, to an address read from settings. See AGENTS.md.',
};

const PURE_ANALYSIS = 'src/analysis/ is pure so the engine runs under Vitest in Node. See AGENTS.md.';
const ANALYSIS_GLOBALS = ['chrome', 'document', 'window', 'navigator', 'localStorage'].map((name) => ({
  name,
  message: PURE_ANALYSIS,
}));
const DATE_NOW = {
  object: 'Date',
  property: 'now',
  message: `${PURE_ANALYSIS} Take the time as an injected parameter.`,
};

export default tseslint.config(
  {
    ignores: ['dist/**', 'harness/.build/**', 'coverage/**', 'node_modules/**'],
  },

  // Type-aware linting for everything TypeScript.
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // --- Explicitly required by the project brief -------------------------
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unsafe-assignment': 'error',
      '@typescript-eslint/no-unsafe-member-access': 'error',
      '@typescript-eslint/no-unsafe-call': 'error',
      '@typescript-eslint/no-unsafe-return': 'error',
      '@typescript-eslint/no-unsafe-argument': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrors: 'all', caughtErrorsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',

      // --- Security posture: attacker-controlled email content -------------
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
      'no-restricted-properties': ['error', ...HTML_SINK_PROPERTIES],
      'no-restricted-globals': ['error', ...BASE_GLOBALS],
      // `srcdoc` is an HTML sink reached by assignment or attribute, neither of which is a property read
      // that no-restricted-properties would see.
      'no-restricted-syntax': [
        'error',
        {
          selector: "AssignmentExpression > MemberExpression.left[property.name='srcdoc']",
          message: HOSTILE,
        },
        {
          selector: "CallExpression[callee.property.name='setAttribute'][arguments.0.value=/^srcdoc$/i]",
          message: HOSTILE,
        },
      ],

      // --- House style -----------------------------------------------------
      '@typescript-eslint/consistent-type-imports': ['error', { fixStyle: 'separate-type-imports' }],
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
      '@typescript-eslint/prefer-nullish-coalescing': ['error', { ignoreConditionalTests: true }],
      eqeqeq: ['error', 'always', { null: 'ignore' }],
      'no-console': 'error',
      curly: ['error', 'multi-line'],
    },
  },

  // The service worker is the only network egress in the extension.
  {
    files: ['src/**/*.ts'],
    ignores: ['src/background/**'],
    rules: { 'no-restricted-globals': ['error', ...BASE_GLOBALS, FETCH_GLOBAL] },
  },

  /*
   * The engine touches no browser API. The one deliberate exception is the on-device probe in
   * `llm/on-device.ts`, which looks Chrome's model up through `globalThis` so that every API shape is
   * probed rather than assumed, and so that under Node it simply finds nothing. `globalThis` is left
   * unrestricted for that file's sake; a second use of it in analysis/ deserves the same scrutiny.
   */
  {
    files: ['src/analysis/**/*.ts'],
    rules: {
      'no-restricted-globals': ['error', ...BASE_GLOBALS, FETCH_GLOBAL, ...ANALYSIS_GLOBALS],
      'no-restricted-properties': ['error', ...HTML_SINK_PROPERTIES, DATE_NOW],
    },
  },

  // `now` is an injected option of the engine's entry points; this file supplies its default for
  // production callers. Anything deeper must take the time from its arguments.
  {
    files: ['src/analysis/engine.ts'],
    rules: { 'no-restricted-properties': ['error', ...HTML_SINK_PROPERTIES] },
  },

  // The logger is the single sanctioned console surface.
  {
    files: ['src/shared/logger.ts'],
    rules: { 'no-console': 'off' },
  },

  // Build scripts and configs run in Node and are not part of the extension.
  {
    files: ['scripts/**/*.mjs', 'scripts/**/*.js', '*.config.ts', 'eslint.config.js'],
    rules: {
      'no-console': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
    },
  },

  // Tests may reach into internals and stub odd shapes.
  {
    files: ['test/**/*.ts'],
    rules: {
      // Dangerous-scheme URLs are *test data* here: the suite has to feed `javascript:` and `data:`
      // URLs to the detectors that exist to catch them.
      'no-script-url': 'off',
      // The DOM tests parse Gmail-shaped markup the suite itself wrote, which is the one honest way to
      // reproduce Gmail's structure; nothing parsed here came from a message.
      'no-restricted-globals': [
        'error',
        ...BASE_GLOBALS.filter(({ name }) => name !== 'DOMParser'),
      ],
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
    },
  },

  {
    files: ['**/*.js', '**/*.mjs'],
    ...tseslint.configs.disableTypeChecked,
  },
);
