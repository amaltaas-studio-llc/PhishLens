/**
 * Hinglish (romanised Hindi) wording pack.
 *
 * The commonest form of Indian scam mail in Latin script mixes English nouns (OTP, KYC, UPI PIN,
 * account) with Hindi verbs and particles (karein, batayein, ho jayega, nahi). Markers are the
 * Hindi particles that almost never appear in English; English nouns alone must not qualify the pack.
 */
import { compile, type LanguagePack } from './lexicon.js';

export const hinglish: LanguagePack = {
  id: 'hinglish',
  label: 'Hinglish',
  script: 'latin',
  markers: [
    'hai',
    'hain',
    'nahi',
    'nahin',
    'kya',
    'aap',
    'apka',
    'apki',
    'apke',
    'karo',
    'karein',
    'kare',
    'ji',
    'se',
    'ko',
    'ka',
    'ki',
    'ke',
    'mein',
    'me',
    'aur',
    'par',
    'abhi',
    'jaldi',
  ],
  themes: {
    urgency: [
      compile(String.raw`\b(turant|fauran|abhi|jaldi|bina deri|immediately karo)\b`),
      compile(String.raw`\b(\d{1,2} (minute|minut|ghante|ghanta|din) (mein|me|ke andar))\b`),
      compile(String.raw`\b(last (warning|chance|notice)|antim (chetavani|suchna)|time limit|expire ho)\b`),
      compile(String.raw`\b(warna|agar aap (nahi|nahin))\b[^.!?]{0,30}\b(karenge|karein|update)\b`),
    ],
    credential_verification: [
      compile(
        String.raw`\b(verify|confirm|update|complete|pura)\b[^.!?]{0,40}\b(apka |apna |apni )?(account|kyc|password|login|pehchan|identity)\b`,
      ),
      compile(String.raw`\b(kyc)\b[^.!?]{0,30}\b(update|complete|pura|verify|karo|karein)\b`),
      compile(String.raw`\b(login|sign[- ]?in) (karo|karein|kijiye)\b[^.!?]{0,40}\b(verify|confirm|continue|unblock|restore)\b`),
      compile(String.raw`\b(aadhaar|aadhar|pan)\b[^.!?]{0,40}\b(link|update|verify|karo|karein)\b`),
      compile(String.raw`\baccount\b[^.!?]{0,30}\b(update|verify|confirm) (karo|karein|kijiye)\b`),
    ],
    password_reset_pressure: [
      compile(String.raw`\bpassword\b[^.!?]{0,30}\b(reset|expire|change|update) (ho|karo|karein)?\b`),
      compile(String.raw`\b(reset|change|update) (apka |apna )?password\b`),
    ],
    account_threat: [
      compile(
        String.raw`\b(account|access|profile)\b[^.!?]{0,40}\b(block|suspend|band|deactivate|delete|lock|restrict)\b[^.!?]{0,20}\b(ho jayega|ho jaega|ho jaayega|kar diya|kar denge)?\b`,
      ),
      compile(String.raw`\b(suspicious|unusual|unauthori[sz]ed|anadhikrit)\b[^.!?]{0,30}\b(activity|login|access|sign[- ]?in)\b`),
      compile(String.raw`\b(block|suspend|band) (ho jayega|ho jaega|kar diya jayega|kar diya jaega)\b`),
    ],
    mfa_request: [
      compile(
        String.raw`\b(bhejo|bhejein|batao|batayein|bataye|share karo|share karein|do|dein|send karo)\b[^.!?]{0,40}\b(otp|verification code|security code|upi pin|pin)\b`,
      ),
      compile(
        String.raw`\b(otp|upi pin|verification code)\b[^.!?]{0,40}\b(bhejo|bhejein|batao|batayein|share (karo|karein)|send (karo|karein))\b`,
      ),
      compile(String.raw`\bis (email|mail) ka reply\b[^.!?]{0,40}\b(otp|code|pin)\b`),
    ],
    wire_transfer: [
      compile(String.raw`\b(paise|amount|fund|raashi)\b[^.!?]{0,40}\b(transfer|bhejo|bhejein) (karo|karein)?\b`),
      compile(String.raw`\b(bank transfer|wire transfer|upi) (karo|karein|bhejo)\b`),
    ],
    payment_detail_change: [
      compile(
        String.raw`\b(update|change|naya|nayi)\b[^.!?]{0,40}\b(bank (details|account)|payment (details|info)|account number)\b`,
      ),
      compile(String.raw`\b(hamare|mere) bank details\b[^.!?]{0,30}\b(change|update) (ho gaye|kar diye)\b`),
    ],
    gift_card: [
      compile(String.raw`\b(kharido|kharidein|buy karo)\b[^.!?]{0,40}\b(gift cards?|prepaid cards?|amazon|itunes)\b`),
      compile(String.raw`\b(codes?|pins?)\b[^.!?]{0,40}\b(bhejo|share|photo)\b`),
    ],
    secrecy: [
      compile(String.raw`\b(gupt|confidential|kisi ko mat batana|kisi ko nahi batana|sirf hamare beech)\b`),
      compile(String.raw`\b(kisi (aur |ko bhi )?ko) (mat|nahi|nahin) (batana|batao|batayein)\b`),
    ],
    process_bypass: [
      compile(String.raw`\b(bina|skip|ignore)\b[^.!?]{0,40}\b(approval|verification|process|normal|manzoori)\b`),
      compile(String.raw`\b(call|phone) (nahi|nahin) (le|le paunga|kar sakta)\b`),
    ],
    unusual_request_shape: [
      compile(
        String.raw`^\s*(hi|hello|namaste)?[,\s]*(aap free ho|available ho|ek minute|ek kaam hai|help chahiye)\b`,
      ),
    ],
    prize_lure: [
      compile(String.raw`\b(aap jeet|badhai|selected)\b[^.!?]{0,50}\b(prize|lottery|inamm|reward)\b`),
      compile(String.raw`\b(refund|muavza|inheritance)\b[^.!?]{0,40}\b(pending|unclaimed|approved|available)\b`),
    ],
  },
  negation: {
    before: compile(
      String.raw`\b(kabhi (nahi|nahin)|mat|nahi|nahin|never)\b(?:[^.!?,;]{0,40}\b(?:mang|pooch|ask)\b)?\s{1,3}$`,
    ),
    after: compile(String.raw`^\s{0,40}\b(kabhi (nahi|nahin)|kisi ko (nahi|nahin|mat)|na karein|nahi|nahin)\b`),
    conditional: compile(String.raw`\b(agar|yadi|jab tak)\b[^.!?]{0,40}\b(nahi|nahin|mat)\b`),
  },
  bulk: compile(
    String.raw`\b(unsubscribe|email preferences|preferences manage|ab receive nahi|yeh email isliye|browser mein dekhein)\b`,
  ),
  credentialAsk: compile(
    String.raw`\b(password|credentials|account verify|otp|kyc|upi pin|login karke verify)\b`,
  ),
  genericSalutation: compile(
    String.raw`\b(priya (customer|grahak|user)|dear (customer|user)|namaste (customer|user))\b`,
  ),
};
