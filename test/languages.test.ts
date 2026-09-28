/**
 * Structural checks on the wording language packs: theme ids, pattern shape, gating, diacritic fold
 * and bidirectional negation. Behaviour against real message shapes lives in `detection.test.ts` via
 * the northwind-* fixtures.
 */
import { describe, expect, it } from 'vitest';
import { __testables as contentTestables } from '../src/analysis/rules/content.js';
import {
  LANGUAGE_PACKS,
  THEME_IDS,
  compile,
  detectLanguages,
  foldLatinDiacritics,
} from '../src/analysis/rules/languages/index.js';
import { normalizeForMatching } from '../src/shared/text.js';

const THEME_ID_SET = new Set<string>(THEME_IDS);

describe('language packs', () => {
  it('every pack theme id exists on the English content table', () => {
    const englishIds = new Set(contentTestables.CONTENT_PATTERNS.map((pattern) => pattern.id));
    for (const pack of LANGUAGE_PACKS) {
      for (const themeId of Object.keys(pack.themes)) {
        expect(THEME_ID_SET.has(themeId), `${pack.id}.${themeId}`).toBe(true);
        expect(englishIds.has(themeId as (typeof THEME_IDS)[number]), `${pack.id}.${themeId}`).toBe(
          true,
        );
      }
    }
  });

  it('every pack pattern is compiled with a Unicode-aware boundary', () => {
    for (const pack of LANGUAGE_PACKS) {
      for (const [themeId, patterns] of Object.entries(pack.themes)) {
        for (const pattern of patterns) {
          // ASCII `\b` must not survive compile(); the Unicode stand-in uses lookaround on `\p{L}`.
          expect(pattern.source.includes('\\b'), `${pack.id}.${themeId}`).toBe(false);
          expect(pattern.flags.includes('u'), `${pack.id}.${themeId}`).toBe(true);
        }
      }
    }
  });

  it('keeps pattern gaps bounded so hostile input cannot force pathological matching', () => {
    for (const pack of LANGUAGE_PACKS) {
      for (const [themeId, patterns] of Object.entries(pack.themes)) {
        for (const pattern of patterns) {
          // Same shape rule as the English table: quantified gaps must be capped.
          expect(pattern.source, `${pack.id}.${themeId}`).not.toMatch(
            /(?:\.\*|[^\\]\{\d*,\}|\+\+|\{,\d*\})/u,
          );
        }
      }
    }
  });

  it('folds Latin diacritics without changing string length', () => {
    const samples = ['café', 'vérifier', 'contraseña', 'nação', 'für', 'più', 'aapka'];
    for (const sample of samples) {
      const folded = foldLatinDiacritics(sample);
      expect(folded.length).toBe(sample.length);
    }
    expect(foldLatinDiacritics('café')).toBe('cafe');
    expect(foldLatinDiacritics('vérifier')).toBe('verifier');
    expect(foldLatinDiacritics('für')).toBe('fur');
  });

  it('matches accentless spellings against accented patterns', () => {
    const pattern = compile(String.raw`\bvérifier\b`);
    expect(pattern.test(foldLatinDiacritics('debe verifier su cuenta'))).toBe(true);
    expect(pattern.test(foldLatinDiacritics('debe vérifier su cuenta'))).toBe(true);
  });

  it('does not activate a Latin pack on ordinary English mail', () => {
    const english = normalizeForMatching(
      'Your verification code is 482915. Never share your verification code with anyone. Enter it on the sign-in screen. Northwind Tools staff will never ask you to send us your verification code by email, phone or chat.',
    );
    const active = detectLanguages(foldLatinDiacritics(english)).map((pack) => pack.id);
    expect(active).toEqual([]);
  });

  it('activates the matching pack for each language fixture body', () => {
    const samples: Record<string, string> = {
      es: 'Estimado cliente, debe verificar su cuenta inmediatamente porque hemos detectado actividad sospechosa en las proximas horas. Actue ahora. Gracias.',
      fr: 'Cher client, vous devez verifier votre compte immediatement. Merci, nous avons detecte une activite suspecte dans les dernieres heures pour votre securite.',
      de: 'Sehr geehrter Kunde, sie mussen ihr Konto sofort bestatigen und die Sperrung vermeiden. Wir haben verdachtige Aktivitat auf dem Konto festgestellt, bitte handeln sie oder ihr Zugang wird gesperrt.',
      pt: 'Prezado cliente, voce deve verificar sua conta imediatamente. Obrigado, detectamos atividade suspeita na sua conta e voce precisa agir agora para evitar o bloqueio.',
      it: 'Gentile cliente, deve verificare il suo account immediatamente. Questo messaggio e automatico e non richiede una risposta. Grazie.',
      nl: 'Beste klant, u moet uw account onmiddellijk verifiëren. Ook hebben we verdachte activiteit gedetecteerd op dit account voor uw veiligheid.',
      hinglish: 'Priya customer, aapko apna kyc turant update karna hoga. Account block ho jayega. Abhi login karein aur verify karein.',
    };
    for (const [id, body] of Object.entries(samples)) {
      const active = detectLanguages(foldLatinDiacritics(normalizeForMatching(body))).map(
        (pack) => pack.id,
      );
      expect(active, id).toContain(id);
    }
  });

  it('activates Hindi on Devanagari letter share, not on Latin markers alone', () => {
    const hindi = normalizeForMatching(
      'प्रिय ग्राहक, आपको अपना केवायसी तुरंत अपडेट करना होगा नहीं तो खाता ब्लॉक हो जाएगा।',
    );
    const active = detectLanguages(foldLatinDiacritics(hindi)).map((pack) => pack.id);
    expect(active).toContain('hi');
  });

  it('treats after-verb negation as reversing a solicitation', () => {
    // German: negation follows the object. Without looking after the match this fires as a request.
    // Enough markers that the pack actually runs: und/sich/oder/auf/den/wir/sie/ihr/haben.
    const german = foldLatinDiacritics(
      normalizeForMatching(
        'Teilen Sie Ihren Bestätigungscode niemals mit anderen. Wir haben den Code auf dem Konto und sie oder ihr Team werden ihn nicht von uns erfragen.',
      ),
    );
    const packs = detectLanguages(german);
    expect(packs.some((pack) => pack.id === 'de')).toBe(true);
    const dePatterns = packs.find((pack) => pack.id === 'de')?.themes.mfa_request ?? [];
    const hits = dePatterns.flatMap((pattern) => {
      const match = pattern.exec(german);
      return match?.index === undefined ? [] : [{ index: match.index, length: match[0].length }];
    });
    expect(hits.length).toBeGreaterThan(0);
    for (const hit of hits) {
      expect(contentTestables.isNegated(german, hit.index, hit.length, packs)).toBe(true);
    }
  });

  it('keeps a conditional demand reportable despite a negation word', () => {
    const spanish = foldLatinDiacritics(
      normalizeForMatching(
        'Si usted no verifica su cuenta sera suspendida en las proximas horas. Debe verificar su cuenta ahora. Gracias.',
      ),
    );
    const packs = detectLanguages(spanish);
    expect(packs.some((pack) => pack.id === 'es')).toBe(true);
    // The second sentence is an unconditional ask and must still match.
    const esPatterns = packs.find((pack) => pack.id === 'es')?.themes.credential_verification ?? [];
    expect(esPatterns.some((pattern) => pattern.test(spanish))).toBe(true);
  });
});
