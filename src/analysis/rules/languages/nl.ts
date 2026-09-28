/**
 * Dutch wording pack.
 */
import { compile, type LanguagePack } from './lexicon.js';

export const nl: LanguagePack = {
  id: 'nl',
  label: 'Dutch',
  script: 'latin',
  // Prefer words that are rare as whole tokens in English — Dutch shares many short particles with
  // English ("is", "in", "de"), and those alone must not qualify the pack on ordinary English mail.
  markers: [
    'het',
    'een',
    'niet',
    'voor',
    'zijn',
    'ook',
    'bij',
    'dat',
    'naar',
    'nog',
    'wel',
    'geen',
    'worden',
    'kan',
    'moet',
    'jullie',
    'deze',
    'dit',
    'uw',
    'alsjeblieft',
  ],
  themes: {
    urgency: [
      compile(String.raw`\b(onmiddellijk|dringend|urgent|meteen|zonder uitstel|zo snel mogelijk)\b`),
      compile(String.raw`\b(binnen|in) (de komende )?\d{1,2} (minuten?|uren?|dagen?)\b`),
      compile(String.raw`\b(verloopt|verloopdatum|deadline|laatste (bericht|herinnering|dag)|handel (nu|direct)|niet wachten)\b`),
      compile(String.raw`\b(voordat het te laat is|als u (niet )?(handelt|reageert|antwoordt))\b`),
    ],
    credential_verification: [
      compile(
        String.raw`\b(verifieer|verifiëren|bevestig|bevestigen|valideer|werk bij|opnieuw invoeren)\b[^.!?]{0,40}\b(uw |jouw )?(account|identiteit|wachtwoord|inloggegevens|toegang|aanmelding)\b`,
      ),
      compile(
        String.raw`\b(log in|aanmelden)\b[^.!?]{0,40}\b(om te (verifiëren|bevestigen|doorgaan|herstellen|deblokkeren)|onmiddellijk|nu)\b`,
      ),
      compile(String.raw`\b(klik|tik)\b[^.!?]{0,30}\b(link|knop|hier)\b[^.!?]{0,40}\b(inloggen|verifiëren|bevestigen)\b`),
      compile(String.raw`\b(uw )?wachtwoord (verloopt|moet (worden )?(bijgewerkt|gewijzigd|gereset))\b`),
    ],
    password_reset_pressure: [
      compile(String.raw`\bwachtwoord\b[^.!?]{0,30}\b(reset|verloop|verlopen|wijzig|bijwerk)\w*\b`),
      compile(String.raw`\b(reset|wijzig|bijwerken) (uw )?wachtwoord\b`),
    ],
    account_threat: [
      compile(
        String.raw`\b(account|toegang|profiel|mailbox|abonnement)\b[^.!?]{0,40}\b(opgeschort|geblokkeerd|gedeactiveerd|verwijderd|beperkt|gesloten)\b`,
      ),
      compile(String.raw`\b(ongebruikelijke|verdachte|ongeautoriseerde|onbekende) (aanmelding|activiteit|toegang)\b`),
      compile(String.raw`\bom (de )?(opschorting|deactivering|verwijdering|blokkering|sluiting) te (voorkomen|vermijden)\b`),
    ],
    mfa_request: [
      compile(
        String.raw`\b(deel|stuur|geef|verstuur|noem|doorsturen)\b[^.!?]{0,40}\b(otp|verificatiecode|beveiligingscode|authenticatiecode|eenmalige (code|wachtwoord)|sms[- ]?code|toegangscode)\b`,
      ),
      compile(
        String.raw`\b(antwoord|reageer op deze e[- ]?mail)\b[^.!?]{0,40}\b(met|en stuur)\b[^.!?]{0,40}\b(otp|code|verificatiecode)\b`,
      ),
    ],
    wire_transfer: [
      compile(String.raw`\b(overschrijving|bankoverschrijving|geldoverdracht)\b`),
      compile(String.raw`\b(maak over|overmaken|overboeken|stuur|verzenden)\b[^.!?]{0,40}\b(geld|bedrag|betaling|middelen)\b`),
      compile(String.raw`\b(iban|swift[- ]?code|bic|rekeningnummer|bankgegevens)\b`),
    ],
    payment_detail_change: [
      compile(
        String.raw`\b(werk bij|wijzig|nieuwe|andere)\b[^.!?]{0,40}\b(bankgegevens|betaalgegevens|rekeninggegevens)\b`,
      ),
      compile(String.raw`\b(onze|mijn|de) bankgegevens (zijn |zijn )?(gewijzigd|bijgewerkt)\b`),
    ],
    gift_card: [
      compile(
        String.raw`\b(koop|kopen|schaf aan|aanschaffen)\b[^.!?]{0,40}\b(cadeaukaarten?|prepaidkaarten?|tegoeden?|amazon|itunes)\b`,
      ),
      compile(String.raw`\b(stuur|deel|fotografeer)\b[^.!?]{0,40}\b(codes?|pinnen?)\b[^.!?]{0,40}\b(kaarten?|tegoeden?)\b`),
    ],
    secrecy: [
      compile(String.raw`\b(houd (dit|het) (tussen ons|vertrouwelijk|privé|geheim)|vertel (het )?aan niemand|niet bespreken|niet noemen)\b`),
      compile(String.raw`\b(vertrouwelijke|discrete|priv[eé]) (zaak|verzoek|transactie)\b`),
      compile(String.raw`\b(niemand|geen ander) (mag|hoeft|moet) (het )?weten\b`),
    ],
    process_bypass: [
      compile(
        String.raw`\b(sla over|omzeil|zonder|geen behoefte aan|negeer)\b[^.!?]{0,40}\b(goedkeuring|autorisatie|verificatie|procedure|proces|gebruikelijke (kanalen?|weg))\b`,
      ),
      compile(String.raw`\b(kan|zal) (ik )?(geen )?(gesprekken?|telefoontjes?) (aannemen|nemen)|niet bereikbaar\b`),
    ],
    unusual_request_shape: [
      compile(
        String.raw`^\s*(hallo|goedemorgen|goedemiddag|goedenavond)?[,\s]*(bent u (beschikbaar|er|vrij)|heeft u (een )?(minuut|moment)|ik heb een gunst nodig|kunt u me helpen)\b`,
      ),
    ],
    prize_lure: [
      compile(String.raw`\b(u heeft gewonnen|gefeliciteerd|u bent geselecteerd)\b[^.!?]{0,50}\b(prijs|loterij|beloning|winst)\b`),
      compile(String.raw`\b(terugbetaling|vergoeding|erfenis)\b[^.!?]{0,40}\b(openstaand|niet opge[eë]ist|goedgekeurd|beschikbaar)\b`),
    ],
  },
  negation: {
    before: compile(
      String.raw`\b(nooit|niet|geen)\b(?:[^.!?,;]{0,40}\b(?:vragen|vraagt|verzoeken|eisen|eis)\b[^.!?,;]{0,20}\b(?:om|dat))?\s{1,3}$`,
    ),
    after: compile(String.raw`^\s{0,40}\b(nooit|niet|aan niemand|met niemand)\b`),
    conditional: compile(String.raw`\b(als|indien|tenzij|wanneer)\b[^.!?]{0,40}\b(niet|geen)\b`),
  },
  bulk: compile(
    String.raw`\b(uitschrijven|afmelden|abonnement opzeggen|e[- ]?mailvoorkeuren|voorkeuren beheren|geen e[- ]?mails? meer|deze e[- ]?mail in (uw )?browser bekijken|u ontvangt deze (e[- ]?mail|bericht) omdat)\b`,
  ),
  credentialAsk: compile(
    String.raw`\b(wachtwoord|inloggegevens|account verifiëren|log in om te (verifiër|bevestig)|otp|verificatiecode|eenmalige code)\b`,
  ),
  genericSalutation: compile(
    String.raw`\b(beste (klant|gebruiker|lid|rekeninghouder)|hallo (klant|gebruiker)|attentie:? (klant|gebruiker))\b`,
  ),
};
