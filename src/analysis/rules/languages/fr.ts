/**
 * French wording pack.
 *
 * Negation often wraps the verb ("ne … jamais", "ne … pas"), so both `before` and `after` matter:
 * "Ne partagez jamais votre code" puts "ne" before and "jamais" after the verb.
 */
import { compile, type LanguagePack } from './lexicon.js';

export const fr: LanguagePack = {
  id: 'fr',
  label: 'French',
  script: 'latin',
  // Accentless: gating runs on diacritic-folded text. Prefer words rare as whole English tokens.
  markers: [
    'les',
    'des',
    'une',
    'que',
    'qui',
    'pour',
    'dans',
    'avec',
    'cette',
    'votre',
    'nous',
    'vous',
    'sont',
    'mais',
    'tout',
    'aussi',
    'etre',
    'avoir',
    'merci',
    'bonjour',
  ],
  themes: {
    urgency: [
      compile(String.raw`\b(imm[eé]diatement|urgent|urgemment|tout de suite|sans d[eé]lai|d[eè]s que possible|au plus vite)\b`),
      compile(String.raw`\b(dans|sous) (les? )?\d{1,2} (minutes?|heures?|jours?)\b`),
      compile(String.raw`\b(expire|expiration|date limite|dernier (avis|rappel|jour)|agissez (maintenant|vite)|ne tardez pas)\b`),
      compile(String.raw`\b(avant qu'?il ne soit trop tard|si vous (ne )?(agissez|r[eé]pondez) pas)\b`),
    ],
    credential_verification: [
      compile(
        String.raw`\b(v[eé]rifiez|v[eé]rifier|confirmez|confirmer|validez|valider|mettez [aà] jour|renseignez)\b[^.!?]{0,40}\b(votre |vos )?(compte|identit[eé]|mot de passe|identifiants?|connexion|acc[eè]s)\b`,
      ),
      compile(
        String.raw`\b(connectez[- ]vous|se connecter)\b[^.!?]{0,40}\b(pour (v[eé]rifier|confirmer|continuer|[eé]viter|r[eé]tablir|d[eé]bloquer)|imm[eé]diatement|maintenant)\b`,
      ),
      compile(String.raw`\b(cliquez|tapez)\b[^.!?]{0,30}\b(lien|bouton|ici)\b[^.!?]{0,40}\b(connecter|v[eé]rifier|confirmer)\b`),
      compile(String.raw`\b(votre )?mot de passe (va )?expirer[a]?|doit [eê]tre (mis [aà] jour|chang[eé]|r[eé]initialis[eé])\b`),
    ],
    password_reset_pressure: [
      compile(String.raw`\bmot de passe\b[^.!?]{0,30}\b(r[eé]initialis|expir|chang|mis [aà] jour)\w*\b`),
      compile(String.raw`\b(r[eé]initialiser|changer|mettre [aà] jour) (votre )?mot de passe\b`),
    ],
    account_threat: [
      compile(
        String.raw`\b(compte|acc[eè]s|profil|bo[iî]te mail|abonnement)\b[^.!?]{0,40}\b(suspend|bloqu|d[eé]sactiv|supprim|ferm|restreint|limit)\w*\b`,
      ),
      compile(String.raw`\b(activit[eé]|connexion|acc[eè]s) (inhabituelle|suspecte|non autoris[eée]|non reconnue)\b`),
      compile(String.raw`\bpour ([eé]viter|pr[eé]venir) (la )?(suspension|d[eé]sactivation|fermeture|suppression|blocage)\b`),
    ],
    mfa_request: [
      compile(
        String.raw`\b(partagez|envoyez|fournissez|transmettez|indiquez|donnez|dites[- ]nous)\b[^.!?]{0,40}\b(otp|code (de )?(v[eé]rification|s[eé]curit[eé]|authentification|acc[eè]s)|mot de passe [aà] usage unique|code sms)\b`,
      ),
      compile(
        String.raw`\b(r[eé]pondez|r[eé]pondez [aà] cet e[- ]?mail)\b[^.!?]{0,40}\b(avec|en indiquant)\b[^.!?]{0,40}\b(otp|code)\b`,
      ),
    ],
    wire_transfer: [
      compile(String.raw`\b(virement|transfert) (bancaire|de fonds|urgent)\b`),
      compile(String.raw`\b(virer|transf[eé]rer|envoyer|effectuer)\b[^.!?]{0,40}\b(fonds?|argent|paiement|montant)\b`),
      compile(String.raw`\b(iban|code (swift|bic)|coordonn[eé]es bancaires|num[eé]ro de compte)\b`),
    ],
    payment_detail_change: [
      compile(
        String.raw`\b(mettez [aà] jour|modifier|changez|nouveaux?|diff[eé]rents?)\b[^.!?]{0,40}\b(coordonn[eé]es|informations?|compte) (bancaires?|de paiement)\b`,
      ),
      compile(String.raw`\b(nos|mes|les) coordonn[eé]es bancaires (ont|ont [eé]t[eé]) (chang|modifi|mis)\w*\b`),
    ],
    gift_card: [
      compile(
        String.raw`\b(achetez|acheter|procurez[- ]vous|obtenez)\b[^.!?]{0,40}\b(cartes?|bons?) (cadeaux?|pr[eé]pay[eé]es?|amazon|itunes)\b`,
      ),
      compile(String.raw`\b(envoyez|partagez|photographiez)\b[^.!?]{0,40}\b(codes?|pins?)\b[^.!?]{0,40}\b(cartes?|bons?)\b`),
    ],
    secrecy: [
      compile(String.raw`\b(gardez (ceci|cela) (entre nous|confidentiel|priv[eé]|secret)|ne (le )?(dites|mentionnez|parlez) (pas|à personne))\b`),
      compile(String.raw`\b(affaire|demande|transaction) (confidentielle|discr[eè]te|priv[eée])\b`),
      compile(String.raw`\b(personne|nul) (d'autre )?(ne )?(doit|a besoin de) (savoir|être au courant)\b`),
    ],
    process_bypass: [
      compile(
        String.raw`\b(contournez|ignorer|sans|pas besoin de|sautez)\b[^.!?]{0,40}\b(approbation|autorisation|v[eé]rification|proc[eé]dure|processus|canaux? habituels?)\b`,
      ),
      compile(String.raw`\b(je (ne )?(peux|pourrai) pas)\b[^.!?]{0,40}\b(prendre (d[e']? ?)?(appels?|le t[eé]l[eé]phone)|appeler|parler|me r[eé]unir)\b`),
    ],
    unusual_request_shape: [
      compile(
        String.raw`^\s*(bonjour|bonsoir|salut)?[,\s]*(êtes[- ]vous (disponible|là|libre)|avez[- ]vous (une? )?(minute|moment)|j'ai besoin d'un service|pouvez[- ]vous m'aider)\b`,
      ),
    ],
    prize_lure: [
      compile(String.raw`\b(vous avez gagn[eé]|f[eé]licitations|vous avez [eé]t[eé] s[eé]lectionn[eé])\b[^.!?]{0,50}\b(prix|loterie|r[eé]compense|gain)\b`),
      compile(String.raw`\b(remboursement|indemnit[eé]|h[eé]ritage)\b[^.!?]{0,40}\b(en attente|non r[eé]clam[eé]|approuv[eé]|disponible)\b`),
    ],
  },
  negation: {
    // "ne vous demandera jamais de nous envoyer le code": the ask-verb must reach the solicitation.
    before: compile(
      String.raw`\b(ne|n'|jamais|nullement)\b(?:[^.!?,;]{0,50}\b(?:demander\w*|exiger\w*)\b[^.!?,;]{0,40}\b(?:de|que))?\s{1,3}$`,
    ),
    after: compile(String.raw`^\s{0,40}\b(jamais|pas|à personne|a personne)\b`),
    conditional: compile(String.raw`\b(si|sauf si|à moins que|lorsque)\b[^.!?]{0,40}\b(ne|n'|pas)\b`),
  },
  bulk: compile(
    String.raw`\b(se d[eé]sabonner|d[eé]sabonnement|g[eé]rer (vos )?pr[eé]f[eé]rences|pr[eé]f[eé]rences (de |d')?(e[- ]?mail|courriel)|ne plus recevoir|voir (cet )?e[- ]?mail dans (votre )?navigateur|vous recevez (cet?|ce) (e[- ]?mail|message) parce que)\b`,
  ),
  credentialAsk: compile(
    String.raw`\b(mot de passe|identifiants?|v[eé]rifier (votre )?compte|connectez[- ]vous pour (v[eé]rifi|confirma)|otp|code (de )?(v[eé]rification|[aà] usage unique))\b`,
  ),
  genericSalutation: compile(
    String.raw`\b(cher(?:e)? (client|utilisateur|membre|titulaire)|bonjour (client|utilisateur)|attention:? (client|utilisateur)|cher client)\b`,
  ),
};
