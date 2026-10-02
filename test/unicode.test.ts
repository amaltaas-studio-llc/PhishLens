/**
 * Unicode spoofing primitives.
 *
 * These back the homoglyph, punycode, and filename-direction findings. They are the least intuitive
 * code in the project and the easiest place to be quietly wrong, so the cases below use the actual
 * characters an attacker would use rather than describing them.
 */
import { describe, expect, it } from 'vitest';
import {
  decodeIdnHost,
  editDistance,
  hasBidiOrInvisible,
  hasDirectionControl,
  hasStyledLetterforms,
  hasSuspiciousScriptMixing,
  isConfusableWith,
  punycodeDecodeLabel,
  scriptsUsed,
  skeleton,
  stripBidiAndInvisible,
} from '../src/shared/unicode.js';
import { normalizeForMatching, parseMailbox } from '../src/shared/text.js';

describe('punycodeDecodeLabel', () => {
  it.each([
    // The canonical apple.com homograph.
    ['xn--80ak6aa92e', 'аррӏе'],
    ['xn--mnchen-3ya', 'münchen'],
  ])('decodes %s', (encoded, expected) => {
    expect(punycodeDecodeLabel(encoded.replace(/^xn--/u, ''))).toBe(expected);
  });

  it('agrees with the platform IDNA encoder, which is the only authority worth checking against', () => {
    for (const unicodeHost of ['münchen.de', 'аррӏе.com', 'телеграм.org', 'παράδειγμα.gr']) {
      const encodedLabel = new URL(`https://${unicodeHost}`).hostname.split('.')[0] ?? '';
      expect(encodedLabel.startsWith('xn--')).toBe(true);
      expect(punycodeDecodeLabel(encodedLabel.slice(4))).toBe(unicodeHost.split('.')[0]);
    }
  });

  it('returns null for input that is not valid punycode, rather than guessing', () => {
    expect(punycodeDecodeLabel('!!!invalid!!!')).toBeNull();
    expect(punycodeDecodeLabel('')).toBeNull();
  });

  it('never throws on hostile input', () => {
    const hostile = ['-'.repeat(1000), 'zzzzzzzzzzzzzzzzzzzz', '\u0000', 'a'.repeat(10_000)];
    for (const input of hostile) {
      expect(() => punycodeDecodeLabel(input)).not.toThrow();
    }
  });
});

describe('decodeIdnHost', () => {
  it('renders a punycode host the way the browser address bar would', () => {
    expect(decodeIdnHost('xn--80ak6aa92e.com')).toBe('аррӏе.com');
  });

  it('leaves an ASCII host untouched', () => {
    expect(decodeIdnHost('login.example.com')).toBe('login.example.com');
  });

  it('decodes only the labels that are encoded', () => {
    expect(decodeIdnHost('login.xn--mnchen-3ya.de')).toBe('login.münchen.de');
  });

  it('leaves an undecodable label as-is instead of dropping it', () => {
    expect(decodeIdnHost('xn--!!!.com')).toBe('xn--!!!.com');
  });
});

describe('script mixing', () => {
  it('names the scripts present in a string', () => {
    expect(scriptsUsed('paypal')).toEqual(['Latin']);
    expect(scriptsUsed('раypal')).toContain('Cyrillic');
    expect(scriptsUsed('раypal')).toContain('Latin');
  });

  it('flags a label that mixes Latin with a confusable script', () => {
    // "аpple" with a Cyrillic а: visually identical, a different domain entirely.
    expect(hasSuspiciousScriptMixing('аpple')).toBe(true);
    expect(hasSuspiciousScriptMixing('раypal')).toBe(true);
  });

  it('does not flag legitimate single-script names', () => {
    expect(hasSuspiciousScriptMixing('apple')).toBe(false);
    expect(hasSuspiciousScriptMixing('münchen')).toBe(false);
    expect(hasSuspiciousScriptMixing('телеграм')).toBe(false);
  });

  it('does not flag digits or hyphens mixed with letters', () => {
    expect(hasSuspiciousScriptMixing('office365')).toBe(false);
    expect(hasSuspiciousScriptMixing('my-bank-2024')).toBe(false);
  });
});

describe('bidi and invisible characters', () => {
  it('detects a right-to-left override, the classic filename trick', () => {
    // `invoice\u202Egnp.exe` renders as `invoiceexe.png`.
    expect(hasBidiOrInvisible('invoice\u202Egnp.exe')).toBe(true);
  });

  it.each([
    ['zero-width space', 'pay\u200bpal.com'],
    ['zero-width joiner', 'pay\u200dpal.com'],
    ['left-to-right mark', 'paypal\u200e.com'],
    ['byte-order mark', '\ufeffpaypal.com'],
    ['soft hyphen', 'pay\u00adpal.com'],
  ])('detects a %s', (_label, input) => {
    expect(hasBidiOrInvisible(input)).toBe(true);
  });

  it('does not flag ordinary text', () => {
    expect(hasBidiOrInvisible('invoice-2024.pdf')).toBe(false);
    expect(hasBidiOrInvisible('Zahlungsbestätigung.pdf')).toBe(false);
  });

  it('strips the hidden characters so the real string can be shown to the user', () => {
    expect(stripBidiAndInvisible('invoice\u202Egnp.exe')).toBe('invoicegnp.exe');
    expect(stripBidiAndInvisible('pay\u200bpal.com')).toBe('paypal.com');
    expect(stripBidiAndInvisible('clean.txt')).toBe('clean.txt');
  });

  it.each([
    ['invisible times', 'pass\u2062word'],
    ['function application', 'pass\u2061word'],
    ['combining grapheme joiner', 'pass\u034fword'],
    ['pop directional formatting', 'pass\u202cword'],
    ['left-to-right isolate', 'pass\u2066word'],
    ['Hangul filler', 'pass\u3164word'],
  ])('detects and strips a %s', (_label, input) => {
    expect(hasBidiOrInvisible(input)).toBe(true);
    expect(stripBidiAndInvisible(input)).toBe('password');
  });

  it('leaves emoji presentation selectors alone, which change nothing a reader is shown', () => {
    expect(hasBidiOrInvisible('ok \u2764\ufe0f')).toBe(false);
  });

  it('tells characters that reorder text from characters that only hide in it', () => {
    expect(hasDirectionControl('invoice\u202Egnp.exe')).toBe(true);
    expect(hasDirectionControl('report\u2067.pdf')).toBe(true);
    expect(hasDirectionControl('invoice.ex\u00ade')).toBe(false);
    expect(hasDirectionControl('invoice.ex\u200be')).toBe(false);
  });
});

describe('the same invisible set in matching text', () => {
  it('lets a content rule read a keyword split by any character the identity rules strip', () => {
    expect(normalizeForMatching('Pass\u2062word')).toBe('password');
    expect(normalizeForMatching('Pass\u3164word')).toBe('password');
  });

  it("folds German ß onto the ss every pattern is written with", () => {
    expect(normalizeForMatching('Schließung')).toBe('schliessung');
  });
});

describe('parseMailbox on hostile input', () => {
  it('splits a display name from its address', () => {
    expect(parseMailbox('"Dana Whitfield" <Dana@Northwind-Logistics.com>')).toEqual({
      name: 'Dana Whitfield',
      email: 'dana@northwind-logistics.com',
    });
    expect(parseMailbox('dana@northwind-logistics.com')).toEqual({ email: 'dana@northwind-logistics.com' });
    expect(parseMailbox('Dana <not an address>')).toEqual({ name: 'Dana <not an address>' });
    expect(parseMailbox('<@x>')).toEqual({ name: '<@x>' });
  });

  it('stays linear on a header built to make a regex backtrack', () => {
    const hostile = `${'<'.repeat(20_000)}${'a@'.repeat(20_000)}`;
    const started = performance.now();
    parseMailbox(hostile);
    parseMailbox(`x <${'a@'.repeat(20_000)}`);
    expect(performance.now() - started).toBeLessThan(250);
  });
});

describe('skeleton (confusable folding)', () => {
  it('folds visually-identical characters onto one representative', () => {
    // The whole point: these must collide.
    expect(skeleton('раураl')).toBe(skeleton('paypal'));
    expect(skeleton('аpple')).toBe(skeleton('apple'));
  });

  it('folds Latin lookalikes as well as cross-script ones', () => {
    expect(skeleton('rnicrosoft')).toBe(skeleton('microsoft'));
    expect(skeleton('paypa1')).toBe(skeleton('paypal'));
    expect(skeleton('Iogistics')).toBe(skeleton('logistics'));
  });

  it('does not collapse genuinely different words', () => {
    expect(skeleton('microsoft')).not.toBe(skeleton('macrosoft'));
    expect(skeleton('paypal')).not.toBe(skeleton('payment'));
  });

  it('is idempotent, so folding a folded string changes nothing', () => {
    expect(skeleton(skeleton('раураl'))).toBe(skeleton('раураl'));
  });

  it.each([
    ['Cyrillic shha', 'һsbc', 'hsbc'],
    ['Cyrillic palochka', 'аррӏе', 'apple'],
    ['Latin alpha', 'pɑypal', 'paypal'],
    ['Latin script g', 'ɡoogle', 'google'],
  ])('folds a %s onto the letter it is drawn as', (_label, spoof, real) => {
    expect(skeleton(spoof)).toBe(skeleton(real));
  });

  it('reads a Greek capital as the Latin capital it looks like, not as its own lowercase', () => {
    // `Η` lowercases to `η`, which reads as an n; uppercase it is an H.
    expect(skeleton('ΗSBC')).toBe(skeleton('HSBC'));
    expect(skeleton('ΡΑΥΡΑL')).toBe(skeleton('PAYPAL'));
  });
});

describe('isConfusableWith', () => {
  it('matches homoglyph substitutions of a brand name', () => {
    expect(isConfusableWith('rnicrosoft', 'microsoft')).toBe(true);
    expect(isConfusableWith('раypal', 'paypal')).toBe(true);
    expect(isConfusableWith('goog1e', 'google')).toBe(true);
  });

  it('does not match unrelated names', () => {
    expect(isConfusableWith('northwind', 'microsoft')).toBe(false);
    expect(isConfusableWith('example', 'paypal')).toBe(false);
  });

  it('does not report an identical string as confusable', () => {
    // "Confusable" means "renders like the target but is not the target". A domain that *is* the
    // brand's domain must not be reported as imitating it.
    expect(isConfusableWith('paypal', 'paypal')).toBe(false);
  });
});

describe('editDistance', () => {
  it.each([
    ['paypal', 'paypal', 0],
    ['paypal', 'paypa1', 1],
    ['paypal', 'paypall', 1],
    ['paypal', 'papal', 1],
    // Transposition counts as one edit, which is why typosquats like this are caught.
    ['paypal', 'apypal', 1],
  ])('measures %s vs %s as %i', (a, b, expected) => {
    expect(editDistance(a, b)).toBe(expected);
  });

  it('returns max + 1 rather than the true distance once the bound is exceeded', () => {
    // The bound is what keeps a 253-character hostname against 40 brands cheap.
    expect(editDistance('paypal', 'completely-different-string', 3)).toBe(4);
  });

  it('short-circuits on a length difference beyond the bound', () => {
    expect(editDistance('ab', 'abcdefghij', 3)).toBe(4);
  });

  it('handles empty strings', () => {
    expect(editDistance('', '')).toBe(0);
    expect(editDistance('', 'abc', 5)).toBe(3);
    expect(editDistance('abc', '', 5)).toBe(3);
  });

  it('stays fast on adversarially long input', () => {
    const started = Date.now();
    for (let i = 0; i < 200; i++) {
      editDistance('a'.repeat(253), 'microsoft', 3);
    }
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it('is symmetric', () => {
    expect(editDistance('microsoft', 'rnicrosoft', 5)).toBe(editDistance('rnicrosoft', 'microsoft', 5));
  });
});

/**
 * Unicode publishes a bold alphabet for mathematicians, and phishing uses it because a name spelled in it
 * renders normally and matches nothing. The characters below are the real ones, pasted rather than named,
 * because the entire failure mode is that they look identical to what they are not.
 */
describe('hasStyledLetterforms', () => {
  it('finds mathematical alphabets, whatever the style', () => {
    expect(hasStyledLetterforms('\u{1d5e3}aym\u{1d5f2}nt_Declin\u{1d5f2}d')).toBe(true); // sans-serif bold
    expect(hasStyledLetterforms('\u{1d400}\u{1d401}\u{1d402}')).toBe(true); // bold serif
    expect(hasStyledLetterforms('\u{1d4d0}ccount')).toBe(true); // bold script
    expect(hasStyledLetterforms('\u{1d59f}illing')).toBe(true); // fraktur
    expect(hasStyledLetterforms('\u{1d670}\u{1d671}')).toBe(true); // monospace
  });

  it('finds the letterlike symbols that predate those blocks', () => {
    expect(hasStyledLetterforms('\u2102loud Storage')).toBe(true); // double-struck C
    expect(hasStyledLetterforms('\u211brenda')).toBe(true); // script R
  });

  /**
   * The false-positive direction is the one that matters: ordinary international mail is full of accents,
   * currency symbols, emoji and trademark marks, and none of them are letter substitutes.
   */
  it('does not fire on text people actually write', () => {
    for (const text of [
      'Payment Declined',
      'Zo\u00eb M\u00fcller',
      '\u041c\u0438\u0445\u0430\u0438\u043b \u041f\u0435\u0442\u0440\u043e\u0432',
      '\u5c71\u7530\u592a\u90ce',
      'Kestrel Coffee \u2615',
      'ACME\u2122 Billing \u2014 \u00a349.99',
      '',
    ]) {
      expect(hasStyledLetterforms(text), text).toBe(false);
    }
  });

  /**
   * NFKC folds these to plain letters, which is what `normalizeForMatching` relies on to read the claim a
   * styled name is making. Asserted here because that is the property, not an implementation detail.
   */
  it('describes text that NFKC flattens to ASCII', () => {
    const styled = '\u{1d5e3}aym\u{1d5f2}nt';
    expect(hasStyledLetterforms(styled)).toBe(true);
    expect(styled.normalize('NFKC')).toBe('Payment');
  });
});
