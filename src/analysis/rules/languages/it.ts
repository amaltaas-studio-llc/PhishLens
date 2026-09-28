/**
 * Italian wording pack.
 */
import { compile, type LanguagePack } from './lexicon.js';

export const it: LanguagePack = {
  id: 'it',
  label: 'Italian',
  script: 'latin',
  // Accentless: gating runs on diacritic-folded text. Prefer words rare as whole English tokens.
  markers: [
    'una',
    'che',
    'non',
    'del',
    'della',
    'sono',
    'come',
    'questo',
    'questa',
    'anche',
    'tutto',
    'nella',
    'degli',
    'pero',
    'quando',
    'grazie',
    'ciao',
    'siamo',
    'avete',
    'prego',
  ],
  themes: {
    urgency: [
      compile(String.raw`\b(immediatamente|urgente|urgentemente|subito|senza indugio|il prima possibile)\b`),
      compile(String.raw`\b(entro|in) (i prossimi )?\d{1,2} (minuti|ore|giorni)\b`),
      compile(String.raw`\b(scade|scadenza|termine|ultimo (avviso|promemoria|giorno)|agisca (ora|subito)|non ritardi)\b`),
      compile(String.raw`\b(prima che sia troppo tardi|se (lei |tu )?non (agisce|risponde|reagisce))\b`),
    ],
    credential_verification: [
      compile(
        String.raw`\b(verifi(?:chi|care)|confermi|confermare|convalidi|aggiorni|aggiornare|reinserisca)\b[^.!?]{0,40}\b(il |la |il suo |la sua )?(account|conto|identit[aà]|password|credenziali|accesso|login)\b`,
      ),
      compile(
        String.raw`\b(acceda|accedere|effettui (il )?login)\b[^.!?]{0,40}\b(per (verifi(?:care)|confermare|continuare|evitare|ripristinare|sbloccare)|immediatamente|ora)\b`,
      ),
      compile(String.raw`\b(clicchi|tocchi)\b[^.!?]{0,30}\b(link|pulsante|qui)\b[^.!?]{0,40}\b(accedere|verificare|confermare)\b`),
      compile(String.raw`\b(la sua )?password (scadr[aà]|deve (essere )?aggiornata)\b`),
    ],
    password_reset_pressure: [
      compile(String.raw`\bpassword\b[^.!?]{0,30}\b(reimpost|scad|modific|aggiorn)\w*\b`),
      compile(String.raw`\b(reimpostare|modificare|aggiornare) (la sua )?password\b`),
    ],
    account_threat: [
      compile(
        String.raw`\b(account|conto|accesso|profilo|casella|abbonamento)\b[^.!?]{0,40}\b(sospes|bloccat|disattivat|eliminat|chius|limitat|restring)\w*\b`,
      ),
      compile(String.raw`\b(attivit[aà]|accesso|login) (insolita|sospetta|non autorizzat[oa]|non riconosciut[oa])\b`),
      compile(String.raw`\bper (evitare|prevenire) (la )?(sospensione|disattivazione|chiusura|eliminazione|blocco)\b`),
    ],
    mfa_request: [
      compile(
        String.raw`\b(condivida|invii|fornisca|inoltri|indichi|dica|dia)\b[^.!?]{0,40}\b(otp|codice (di )?(verifica|sicurezza|autenticazione|accesso)|password (monouso|usa e getta)|codice sms)\b`,
      ),
      compile(
        String.raw`\b(risponda|risponda a questa e[- ]?mail)\b[^.!?]{0,40}\b(con|includendo)\b[^.!?]{0,40}\b(otp|codice)\b`,
      ),
    ],
    wire_transfer: [
      compile(String.raw`\b(bonifico|trasferimento) (bancario|di fondi|urgente)\b`),
      compile(String.raw`\b(trasferisca|trasferire|invii|inviare|effettui)\b[^.!?]{0,40}\b(fondi|denaro|pagamento|importo)\b`),
      compile(String.raw`\b(iban|codice (swift|bic)|numero di conto|coordinate bancarie)\b`),
    ],
    payment_detail_change: [
      compile(
        String.raw`\b(aggiorni|aggiornare|modifichi|modificare|nuov[oa]i?|divers[oa]i?)\b[^.!?]{0,40}\b(dati|informazioni|coordinate) (bancari[ea]|di pagamento)\b`,
      ),
      compile(String.raw`\b(i nostri|i miei|i) dati bancari (sono|sono stati) (cambi|modific|aggiorn)\w*\b`),
    ],
    gift_card: [
      compile(
        String.raw`\b(acquisti|acquistare|compri|comprare)\b[^.!?]{0,40}\b(carte?|buoni?) (regalo|prepagat[ea]|amazon|itunes)\b`,
      ),
      compile(String.raw`\b(invii|condivida|fotograf[iì])\b[^.!?]{0,40}\b(codici?|pin)\b[^.!?]{0,40}\b(carte?|buoni?)\b`),
    ],
    secrecy: [
      compile(String.raw`\b(mantenga (questo|ci[oò]) (tra noi|riservato|privato|segreto)|non (lo )?dica|non ne parli|non menzioni)\b`),
      compile(String.raw`\b(faccenda|richiesta|transazione) (riservata|discreta|privata|confidenziale)\b`),
      compile(String.raw`\b(nessuno|nessun altro) (deve|ha bisogno di|pu[oò]) sapere\b`),
    ],
    process_bypass: [
      compile(
        String.raw`\b(ignori|ignorare|senza|non c'?[eè] bisogno di|salti|eluda)\b[^.!?]{0,40}\b(approvazione|autorizzazione|verifica|procedura|processo|canali? abituali?)\b`,
      ),
      compile(String.raw`\b(non (posso|potr[oò]))\b[^.!?]{0,40}\b(ricevere (chiamate?|telefonate?)|chiamare|parlare|incontrarmi)\b`),
    ],
    unusual_request_shape: [
      compile(
        String.raw`^\s*(ciao|buongiorno|buonasera)?[,\s]*([eè] (disponibile|l[iì]|libero)|ha (un )?(minuto|momento)|ho bisogno di un favore|pu[oò] aiutarmi)\b`,
      ),
    ],
    prize_lure: [
      compile(String.raw`\b(ha vinto|congratulazioni|[eè] stat[oa] selezionat[oa])\b[^.!?]{0,50}\b(premio|lotteria|ricompensa|vincita)\b`),
      compile(String.raw`\b(rimborso|indennizzo|eredit[aà])\b[^.!?]{0,40}\b(in sospeso|non riscoss[oa]|approvat[oa]|disponibile)\b`),
    ],
  },
  negation: {
    // "non le chiederà mai di inviarci il codice" — reach across the ask-verb to the solicitation.
    before: compile(
      String.raw`\b(mai|non|non deve|non dovete)\b(?:[^.!?,;]{0,50}\b(?:chieder\w*|richieder\w*|esiger\w*)\b[^.!?,;]{0,40}\b(?:di|che))?\s{1,3}$`,
    ),
    after: compile(String.raw`^\s{0,40}\b(mai|a nessuno|con nessuno)\b`),
    conditional: compile(String.raw`\b(se|a meno che|quando|finché)\b[^.!?]{0,40}\bnon\b`),
  },
  bulk: compile(
    String.raw`\b(annulla(?:re)? (l')?iscrizione|disiscriviti|gestisci (le )?preferenze|preferenze (e[- ]?mail|di posta)|non desidera più ricevere|smettere di ricevere|visualizza (questa )?e[- ]?mail nel browser|riceve questa (e[- ]?mail|comunicazione) perch[eé])\b`,
  ),
  credentialAsk: compile(
    String.raw`\b(password|credenziali|verificare (il )?account|acceda per (verifi|conferma)|otp|codice (di )?(verifica|monouso))\b`,
  ),
  genericSalutation: compile(
    String.raw`\b(gentile (cliente|utente|membro|intestatario)|caro cliente|ciao (cliente|utente)|attenzione:? (cliente|utente))\b`,
  ),
};
