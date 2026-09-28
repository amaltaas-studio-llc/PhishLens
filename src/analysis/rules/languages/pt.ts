/**
 * Portuguese wording pack.
 *
 * Covers both European and Brazilian forms where they diverge in phishing copy
 * ("senha"/"palavra-passe", "e-mail"/"email", "você"/"voce").
 */
import { compile, type LanguagePack } from './lexicon.js';

export const pt: LanguagePack = {
  id: 'pt',
  label: 'Portuguese',
  script: 'latin',
  // Accentless: gating runs on diacritic-folded text. Prefer words rare as whole English tokens.
  markers: [
    'uma',
    'que',
    'para',
    'nao',
    'como',
    'mas',
    'seu',
    'sua',
    'este',
    'esta',
    'voce',
    'estao',
    'pelo',
    'pela',
    'quando',
    'tambem',
    'obrigado',
    'obrigada',
    'agora',
    'conta',
  ],
  themes: {
    urgency: [
      compile(String.raw`\b(imediatamente|urgente|urgentemente|agora mesmo|sem demora|o mais r[aá]pido poss[ií]vel)\b`),
      compile(String.raw`\b(em|dentro de) (as? )?\d{1,2} (minutos?|horas?|dias?)\b`),
      compile(String.raw`\b(expira|expira[cç][aã]o|prazo|[uú]ltimo (aviso|lembrete|dia)|aja (agora|j[aá])|n[aã]o demore)\b`),
      compile(String.raw`\b(antes que seja tarde demais|se (voc[eê] )?n[aã]o (agir|responder|contestar))\b`),
    ],
    credential_verification: [
      compile(
        String.raw`\b(verifi(?:que|car)|confirma(?:r|e)|valida(?:r|e)|atualize|atualizar|reinsira)\b[^.!?]{0,40}\b(sua? |suas? )?(conta|identidade|senha|palavra[- ]passe|credenciais|in[ií]cio de sess[aã]o|acesso)\b`,
      ),
      compile(
        String.raw`\b(inicie|fa[cç]a) (sess[aã]o|login)\b[^.!?]{0,40}\b(para (verifi(?:car)|confirma(?:r)|continuar|evitar|restaurar|desbloquear)|imediatamente|agora)\b`,
      ),
      compile(String.raw`\b(clique|toque)\b[^.!?]{0,30}\b(link|bot[aã]o|aqui)\b[^.!?]{0,40}\b(iniciar sess[aã]o|verificar|confirmar)\b`),
      compile(String.raw`\b(sua? )?senha (vai )?expirar|deve (ser )?atualizada\b`),
    ],
    password_reset_pressure: [
      compile(String.raw`\b(senha|palavra[- ]passe)\b[^.!?]{0,30}\b(redefini|expir|alter|atualiz)\w*\b`),
      compile(String.raw`\b(redefinir|alterar|atualizar) (sua? )?(senha|palavra[- ]passe)\b`),
    ],
    account_threat: [
      compile(
        String.raw`\b(conta|acesso|perfil|caixa de entrada|assinatura)\b[^.!?]{0,40}\b(suspend|bloque|desativ|elimin|encerr|restring|limit)\w*\b`,
      ),
      compile(String.raw`\b(atividade|in[ií]cio de sess[aã]o|acesso) (incomum|suspeito|n[aã]o autorizad[oa]|n[aã]o reconhecid[oa])\b`),
      compile(String.raw`\bpara (evitar|impedir) (a )?(suspens[aã]o|desativa[cç][aã]o|encerramento|elimina[cç][aã]o|bloqueio)\b`),
    ],
    mfa_request: [
      // No bare `de`/`dê`: same false positive as Spanish on "código de verificação".
      compile(
        String.raw`\b(compartilhe|envie|forne[cç]a|reenvie|indique|diga|d[eê]-?nos|nos d[eê])\b[^.!?]{0,40}\b(otp|c[oó]digo (de )?(verifica[cç][aã]o|seguran[cç]a|autentica[cç][aã]o|acesso)|senha (de )?uso [uú]nico|pin (do )?upi)\b`,
      ),
      compile(
        String.raw`\b(responda|responda (a )?este (e[- ]?mail|correio))\b[^.!?]{0,40}\b(com|incluindo)\b[^.!?]{0,40}\b(otp|c[oó]digo|pin)\b`,
      ),
    ],
    wire_transfer: [
      compile(String.raw`\b(transfer[eê]ncia|ted|pix) (banc[aá]ria|de fundos|urgente)\b`),
      compile(String.raw`\b(transfira|transferir|enviar|remeter)\b[^.!?]{0,40}\b(fundos?|dinheiro|pagamento|valor)\b`),
      compile(String.raw`\b(iban|c[oó]digo (swift|bic)|n[uú]mero da conta|dados banc[aá]rios)\b`),
    ],
    payment_detail_change: [
      compile(
        String.raw`\b(atualize|atualizar|altere|alterar|nov[oa]s?|diferentes?)\b[^.!?]{0,40}\b(dados|informa[cç][oõ]es|conta) (banc[aá]ri[oa]s?|de pagamento|de dep[oó]sito)\b`,
      ),
      compile(String.raw`\b(nossos|meus|os) dados banc[aá]rios (foram|foram )?(alter|atualiz)\w*\b`),
    ],
    gift_card: [
      compile(
        String.raw`\b(compre|comprar|adquira|adquirir)\b[^.!?]{0,40}\b(cart[oõ]es?|vales?) (presente|pr[eé]-?pago|amazon|itunes)\b`,
      ),
      compile(String.raw`\b(envie|compartilhe|fotografe)\b[^.!?]{0,40}\b(c[oó]digos?|pins?)\b[^.!?]{0,40}\b(cart[oõ]es?|vales?)\b`),
    ],
    secrecy: [
      compile(String.raw`\b(mantenha (isto|isso) (entre n[oó]s|em confidencialidade|em privado|em segredo)|n[aã]o (conte|comente|mencione)|n[aã]o diga a ning[uú][eé]m)\b`),
      compile(String.raw`\b(assunto|pedido|transa[cç][aã]o) (confidencial|discreto|privado)\b`),
      compile(String.raw`\b(ning[uú][eé]m|ningu[eé]m) (mais )?(deve|precisa|pode) saber\b`),
    ],
    process_bypass: [
      compile(
        String.raw`\b(ignore|ignorar|sem|n[aã]o precisa de|pule|omitir)\b[^.!?]{0,40}\b(aprova[cç][aã]o|autoriza[cç][aã]o|verifica[cç][aã]o|procedimento|processo|canais? habituais?)\b`,
      ),
      compile(String.raw`\b(n[aã]o (posso|conseguirei))\b[^.!?]{0,40}\b(atender (chamadas?|o telefone)|ligar|falar|reunir[- ]me)\b`),
    ],
    unusual_request_shape: [
      compile(
        String.raw`^\s*(ol[aá]|bom dia|boa (tarde|noite))?[,\s]*(est[aá] (dispon[ií]vel|a[ií]|livre)|tem (um )?(minuto|momento)|preciso de um favor|pode me ajudar)\b`,
      ),
    ],
    prize_lure: [
      compile(String.raw`\b(voc[eê] ganhou|parab[eé]ns|foi selecionado)\b[^.!?]{0,50}\b(pr[eê]mio|loteria|recompensa|sorteio)\b`),
      compile(String.raw`\b(reembolso|compensa[cç][aã]o|heran[cç]a)\b[^.!?]{0,40}\b(pendente|n[aã]o reclamad[oa]|aprovad[oa]|dispon[ií]vel)\b`),
    ],
  },
  negation: {
    // Same reach-across as English/Spanish: "nunca pedirá que você nos envie o código" is advice.
    before: compile(
      String.raw`\b(nunca|jamais|n[aã]o|n[aã]o deve|n[aã]o deve(?:m)?)\b(?:[^.!?,;]{0,50}\b(?:pedir\w*|solicitar\w*|exigir\w*)\b[^.!?,;]{0,40}\b(?:que)(?:\s{1,3}(?:nos|lhe|lhes|te|me|o|a|se|voc[eê])){0,2})?\s{1,3}$`,
    ),
    after: compile(String.raw`^\s{0,40}\b(nunca|jamais|com ning[uú][eé]m|a ning[uú][eé]m)\b`),
    conditional: compile(String.raw`\b(se|a menos que|quando|enquanto)\b[^.!?]{0,40}\bn[aã]o\b`),
  },
  bulk: compile(
    String.raw`\b(cancelar (a )?inscri[cç][aã]o|descadastrar|gerir (suas? )?prefer[eê]ncias|prefer[eê]ncias de (e[- ]?mail|correio)|n[aã]o deseja mais receber|parar de receber|ver (este )?(e[- ]?mail|correio) no navegador|voc[eê] est[aá] recebendo (este|este) (e[- ]?mail|mensagem) porque)\b`,
  ),
  credentialAsk: compile(
    String.raw`\b(senha|palavra[- ]passe|credenciais|verificar (sua? )?conta|iniciar sess[aã]o para (verifi|confirma)|otp|c[oó]digo de (verifica[cç][aã]o|uso [uú]nico))\b`,
  ),
  genericSalutation: compile(
    String.raw`\b(prezad[oa] (cliente|usu[aá]rio|membro|titular)|caro cliente|ol[aá] (cliente|usu[aá]rio)|aten[cç][aã]o:? (cliente|usu[aá]rio))\b`,
  ),
};
