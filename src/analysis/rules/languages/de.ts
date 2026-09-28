/**
 * German wording pack.
 *
 * Negation commonly follows the verb or object ("Teilen Sie den Code niemals", "geben Sie den Code
 * nicht weiter"), so `after` is the load-bearing direction for MFA and credential themes.
 */
import { compile, type LanguagePack } from './lexicon.js';

export const de: LanguagePack = {
  id: 'de',
  label: 'German',
  script: 'latin',
  // Accentless: gating runs on diacritic-folded text. Prefer words rare as whole English tokens.
  markers: [
    'der',
    'das',
    'und',
    'nicht',
    'eine',
    'sich',
    'auch',
    'oder',
    'fur',
    'auf',
    'dem',
    'den',
    'wir',
    'sie',
    'ihr',
    'sind',
    'haben',
    'werden',
    'bitte',
    'sowie',
  ],
  themes: {
    urgency: [
      compile(String.raw`\b(sofort|umgehend|dringend|unverzüglich|schnellstmöglich|ohne verzug)\b`),
      compile(String.raw`\b(innerhalb|in) (den n[aä]chsten )?\d{1,2} (minuten?|stunden?|tagen?)\b`),
      compile(String.raw`\b(l[aä]uft ab|ablauf|frist|letzte[rs]? (hinweis|erinnerung|tag)|handeln sie (jetzt|sofort)|nicht zögern)\b`),
      compile(String.raw`\b(bevor es zu sp[aä]t ist|wenn sie (nicht )?(handeln|reagieren|antworten))\b`),
    ],
    credential_verification: [
      compile(
        String.raw`\b(best[aä]tigen|überpr[uü]fen|verifizieren|aktualisieren|erneut eingeben)\b[^.!?]{0,40}\b(ihr(?:e[ns]?)? )?(konto|identit[aä]t|passwort|anmeldedaten|zugangsdaten|anmeldung)\b`,
      ),
      compile(
        String.raw`\b(melden sie sich|log(gen)? sie sich|anmelden)\b[^.!?]{0,40}\b(um (zu )?(best[aä]tigen|überpr[uü]fen|fortzufahren|wiederherzustellen)|sofort|jetzt)\b`,
      ),
      compile(String.raw`\b(klicken|tippen) sie\b[^.!?]{0,30}\b(link|schaltfläche|hier)\b[^.!?]{0,40}\b(anmelden|best[aä]tigen|überpr[uü]fen)\b`),
      compile(String.raw`\b(ihr )?passwort (l[aä]uft ab|muss (aktualisiert|ge[aä]ndert|zur[uü]ckgesetzt) werden)\b`),
    ],
    password_reset_pressure: [
      compile(String.raw`\bpasswort\b[^.!?]{0,30}\b(zur[uü]cksetz|ablauf|abgelauf|änder|aktualis)\w*\b`),
      compile(String.raw`\b(zur[uü]cksetzen|ändern|aktualisieren) sie (ihr )?passwort\b`),
    ],
    account_threat: [
      compile(
        String.raw`\b(konto|zugang|profil|postfach|abonnement)\b[^.!?]{0,40}\b(gesperrt|suspendiert|deaktiviert|gel[oö]scht|eingeschr[aä]nkt|blockiert|geschlossen)\b`,
      ),
      compile(String.raw`\b(ungew[oö]hnliche|verd[aä]chtige|unbefugte|unbekannte) (anmeldung|aktivit[aä]t|zugriff)\b`),
      compile(String.raw`\bum (die )?(sperrung|deaktivierung|l[oö]schung|schliessung) zu (vermeiden|verhindern)\b`),
    ],
    mfa_request: [
      compile(
        String.raw`\b(teilen|senden|schicken|geben|nennen|weiterleiten|mitteilen) sie\b[^.!?]{0,40}\b(otp|best[aä]tigungscode|sicherheitscode|verifizierungscode|authentifizierungscode|einmalcode|sms[- ]?code|zugangscode)\b`,
      ),
      compile(
        String.raw`\b(antworten|antworten sie)\b[^.!?]{0,40}\b(mit|und senden)\b[^.!?]{0,40}\b(otp|code|best[aä]tigungscode)\b`,
      ),
    ],
    wire_transfer: [
      compile(String.raw`\b(überweisung|geldtransfer|banküberweisung)\b`),
      compile(String.raw`\b([uü]berweisen|transferieren|senden|anweisen)\b[^.!?]{0,40}\b(geld|betrag|zahlung|mittel)\b`),
      compile(String.raw`\b(iban|swift[- ]?code|bic|kontonummer|bankverbindung)\b`),
    ],
    payment_detail_change: [
      compile(
        String.raw`\b(aktualisieren|ändern|neue|andere)\b[^.!?]{0,40}\b(bankdaten|bankverbindung|zahlungsdaten|kontoverbindung)\b`,
      ),
      compile(String.raw`\b(unsere|meine|die) bankdaten (haben sich ge[aä]ndert|wurden (ge[aä]ndert|aktualisiert))\b`),
    ],
    gift_card: [
      compile(
        String.raw`\b(kaufen|besorgen|erwerben) sie\b[^.!?]{0,40}\b(geschenkkarten?|gutscheine?|prepaid[- ]?karten?)\b`,
      ),
      compile(String.raw`\b(senden|schicken|teilen|fotografieren) sie\b[^.!?]{0,40}\b(codes?|pins?)\b[^.!?]{0,40}\b(karten?|gutscheine?)\b`),
    ],
    secrecy: [
      compile(String.raw`\b(behalten sie (das|dies) (f[uü]r sich|unter uns|vertraulich)|erz[aä]hlen sie (es )?niemandem|nicht weitererz[aä]hlen|nicht besprechen)\b`),
      compile(String.raw`\b(vertrauliche[rs]?|diskrete[rs]?) (angelegenheit|bitte|transaktion)\b`),
      compile(String.raw`\b(niemand|keiner) (sonst )?(darf|soll|muss) (davon )?wissen\b`),
    ],
    process_bypass: [
      compile(
        String.raw`\b([uü]berspringen|umgehen|ohne|kein bedarf f[uü]r|ignorieren)\b[^.!?]{0,40}\b(genehmigung|freigabe|best[aä]tigung|[uü]berpr[uü]fung|verfahren|prozess|[uü]bliche[rn]? (weg|kanal))\b`,
      ),
      compile(String.raw`\b(kann|werde) (ich |derzeit )?(keine )?(anrufe?|telefonate?) (entgegennehmen|annehmen)|nicht erreichbar\b`),
    ],
    unusual_request_shape: [
      compile(
        String.raw`^\s*(hallo|guten (tag|morgen|abend))?[,\s]*(sind sie (verf[uü]gbar|da|am platz)|haben sie (eine? )?(minute|moment)|ich brauche einen gefallen|k[oö]nnen sie mir helfen)\b`,
      ),
    ],
    prize_lure: [
      compile(String.raw`\b(sie haben gewonnen|herzlichen gl[uü]ckwunsch|sie wurden ausgew[aä]hlt)\b[^.!?]{0,50}\b(preis|lotterie|gewinn|belohnung)\b`),
      compile(String.raw`\b(r[uü]ckerstattung|entsch[aä]digung|erbschaft)\b[^.!?]{0,40}\b(ausstehend|unbeansprucht|genehmigt|verf[uü]gbar)\b`),
    ],
  },
  negation: {
    before: compile(
      String.raw`\b(nie|niemals|nicht|kein(?:e[sn]?)?)\b(?:[^.!?,;]{0,40}\b(?:fragen|fragt|auffordern|verlangen)\b[^.!?,;]{0,20}\b(?:sie|danach))?\s{1,3}$`,
    ),
    after: compile(String.raw`^\s{0,40}\b(nie|niemals|nicht|an niemanden|niemandem)\b`),
    conditional: compile(String.raw`\b(wenn|falls|sofern|bis)\b[^.!?]{0,40}\b(nicht|kein)\b`),
  },
  bulk: compile(
    String.raw`\b(abmelden|abbestellen|newsletter abbestellen|e[- ]?mail[- ]?einstellungen|pr[aä]ferenzen (verwalten|anpassen)|keine (e[- ]?mails?|nachrichten) mehr|diese e[- ]?mail im browser anzeigen|sie erhalten diese (e[- ]?mail|nachricht) weil)\b`,
  ),
  credentialAsk: compile(
    String.raw`\b(passwort|anmeldedaten|konto best[aä]tigen|melden sie sich an um (zu )?(best[aä]tig|überpr[uü]f)|otp|best[aä]tigungscode|einmalcode)\b`,
  ),
  genericSalutation: compile(
    String.raw`\b(sehr geehrte[rs]? (kunde|kundin|nutzer|mitglied|kontoinhaber)|lieber kunde|hallo (kunde|nutzer)|achtung:? (kunde|nutzer))\b`,
  ),
};
