/**
 * Spanish wording pack.
 *
 * Patterns cover the themes that dominate Spanish-language phishing: credential and KYC asks, OTP
 * solicitation, account threats and urgency. Bulk and salutation vocabulary keep newsletters and
 * transactional mail from inheriting those findings.
 */
import { compile, type LanguagePack } from './lexicon.js';

export const es: LanguagePack = {
  id: 'es',
  label: 'Spanish',
  script: 'latin',
  // Accentless: gating runs on diacritic-folded text. Prefer words rare as whole English tokens.
  markers: [
    'los',
    'las',
    'una',
    'que',
    'para',
    'como',
    'pero',
    'sobre',
    'este',
    'esta',
    'usted',
    'ustedes',
    'porque',
    'cuando',
    'tambien',
    'despues',
    'ahora',
    'nuestro',
    'nuestra',
    'gracias',
  ],
  themes: {
    urgency: [
      compile(String.raw`\b(inmediata?mente|urgente|urgentemente|ahora mismo|sin demora|lo antes posible)\b`),
      compile(String.raw`\b(en|dentro de) (las? )?\d{1,2} (minutos?|horas?|d[ií]as?)\b`),
      compile(String.raw`\b(vence|vencimiento|fecha l[ií]mite|[uú]ltimo (aviso|recordatorio|d[ií]a)|act[uú]e (ya|ahora)|no demore)\b`),
      compile(String.raw`\b(antes de que sea demasiado tarde|si (usted )?no (act[uú]a|responde|contesta))\b`),
    ],
    credential_verification: [
      compile(
        String.raw`\b(verifi(?:que|car)|confirma(?:r|e)|valida(?:r|e)|actuali(?:ce|zar)|reingrese)\b[^.!?]{0,40}\b(su |tus? )?(cuenta|identidad|contrase[nñ]a|credenciales|inicio de sesi[oó]n|acceso)\b`,
      ),
      compile(
        String.raw`\b(inicie|inicia) sesi[oó]n\b[^.!?]{0,40}\b(para (verifi(?:car|car)|confirma(?:r)|continuar|evitar|restaurar|desbloquear)|inmediatamente|ahora)\b`,
      ),
      compile(String.raw`\b(haga|haz) clic\b[^.!?]{0,30}\b(enlace|bot[oó]n|aqu[ií])\b[^.!?]{0,40}\b(iniciar sesi[oó]n|verificar|confirmar)\b`),
      compile(String.raw`\b(su |tus? )?contrase[nñ]a (caducar[aá]|expirar[aá]|debe (ser )?actualizada|ha (sido )?comprometida)\b`),
      compile(String.raw`\bactuali(?:ce|zar) (su |tus? )?(kyc|datos (kyc|personales|bancarios))\b`),
    ],
    password_reset_pressure: [
      compile(String.raw`\bcontrase[nñ]a\b[^.!?]{0,30}\b(restablec|caduc|expir|cambi|actualiz)\w*\b`),
      compile(String.raw`\b(restablecer|cambiar|actualizar) (su |tus? )?contrase[nñ]a\b`),
    ],
    account_threat: [
      compile(
        String.raw`\b(cuenta|acceso|perfil|buz[oó]n|suscripci[oó]n)\b[^.!?]{0,40}\b(suspend|bloque|desactiv|elimin|cerrar[aá]|restring|limit)\w*\b`,
      ),
      compile(String.raw`\b(actividad|inicio de sesi[oó]n|acceso) (inusual|sospechoso|no autorizad[oa]|no reconocid[oa])\b`),
      compile(String.raw`\bpara (evitar|prevenir) (la )?(suspensi[oó]n|desactivaci[oó]n|cierre|eliminaci[oó]n|bloqueo)\b`),
    ],
    mfa_request: [
      // No bare `de`/`dé`: it is the commonest Spanish preposition and would match "código de
      // verificación" as a solicitation. Imperative "dénos"/"danos" stays as its own alternative.
      compile(
        String.raw`\b(comparta|envie|env[ií]e|proporcione|reenv[ií]e|indique|diga|d[eé]nos|danos)\b[^.!?]{0,40}\b(otp|c[oó]digo (de )?(verificaci[oó]n|seguridad|autenticaci[oó]n|acceso)|clave (de )?(un solo uso|temporal)|pin (de )?upi)\b`,
      ),
      compile(
        String.raw`\b(responda|conteste|responda a este correo)\b[^.!?]{0,40}\b(con|incluyendo)\b[^.!?]{0,40}\b(otp|c[oó]digo|pin)\b`,
      ),
    ],
    wire_transfer: [
      compile(String.raw`\b(transferencia|giro) (bancaria|de fondos|de dinero|urgente)\b`),
      compile(String.raw`\b(transfiera|transferir|enviar|remitir)\b[^.!?]{0,40}\b(fondos?|dinero|pago|importe)\b`),
      compile(String.raw`\b(iban|c[oó]digo (swift|bic)|n[uú]mero de cuenta|datos bancarios)\b`),
    ],
    payment_detail_change: [
      compile(
        String.raw`\b(actuali(?:ce|zar)|cambi(?:e|ar)|nuev[oa]s?|diferentes?)\b[^.!?]{0,40}\b(datos|informaci[oó]n|cuenta) (bancari[oa]s?|de pago|de dep[oó]sito)\b`,
      ),
      compile(String.raw`\b(nuestros|mis|los) datos bancarios (han|han sido) (cambi|actualiz)\w*\b`),
    ],
    gift_card: [
      compile(
        String.raw`\b(compre|comprar|adquiera|adquirir|consiga)\b[^.!?]{0,40}\b(tarjetas?|vales?) (de )?(regalo|prepago|amazon|itunes)\b`,
      ),
      compile(String.raw`\b(env[ií]e|envie|comparta|fotografie)\b[^.!?]{0,40}\b(c[oó]digos?|pines?)\b[^.!?]{0,40}\b(tarjetas?|vales?)\b`),
    ],
    secrecy: [
      compile(String.raw`\b(mant[eé]ngalo? (entre nosotros|en confidencialidad|en privado|en secreto)|no (se lo )?diga|no comente|no mencione)\b`),
      compile(String.raw`\b(asunto|petici[oó]n|transacci[oó]n) (confidencial|discreto|privado)\b`),
      compile(String.raw`\b(nadie|ninguna persona) (m[aá]s )?(debe|tiene que|puede) saber\b`),
    ],
    process_bypass: [
      compile(
        String.raw`\b(omite|omitir|sin|no hace falta|ignore|salt[eé]se)\b[^.!?]{0,40}\b(aprobaci[oó]n|autorizaci[oó]n|verificaci[oó]n|procedimiento|proceso|canales? habituales?)\b`,
      ),
      compile(String.raw`\b(no (puedo|podr[eé]|estoy en condiciones de))\b[^.!?]{0,40}\b(tomar (llamadas?|el tel[eé]fono)|llamar|hablar|reunirme)\b`),
    ],
    unusual_request_shape: [
      compile(
        String.raw`^\s*(hola|buenos d[ií]as|buenas (tardes|noches))?[,\s]*(est[aá]s? (disponible|ah[ií]|libre)|tienes? (un )?(minuto|momento)|necesito un favor|puedes? ayudarme)\b`,
      ),
    ],
    prize_lure: [
      compile(String.raw`\b(ha? ganado|felicidades|ha sido seleccionado)\b[^.!?]{0,50}\b(premio|loter[ií]a|recompensa|sorteo)\b`),
      compile(String.raw`\b(reembolso|compensaci[oó]n|herencia)\b[^.!?]{0,40}\b(pendiente|sin reclamar|aprobad[oa]|disponible)\b`),
    ],
  },
  negation: {
    // The optional middle is the "nunca le pedirá que nos …" advice shape: without it, the warning
    // next to every genuine code ("nunca pedirá que nos envíe el código") reads as the request.
    before: compile(
      String.raw`\b(nunca|jam[aá]s|no|no debe|no debe(?:n)?|no tiene que)\b(?:[^.!?,;]{0,50}\b(?:pedir\w*|solicitar\w*|requerir\w*)\b[^.!?,;]{0,40}\b(?:que)(?:\s{1,3}(?:nos|le|les|te|me|lo|la|se|usted|ustedes)){0,2})?(?:\s{1,3}(?:nunca|jam[aá]s))?\s{1,3}$`,
    ),
    after: compile(String.raw`^\s{0,40}\b(nunca|jam[aá]s|a nadie)\b`),
    conditional: compile(String.raw`\b(si|a menos que|cuando|mientras)\b[^.!?]{0,40}\bno\b`),
  },
  bulk: compile(
    String.raw`\b(darse de baja|cancelar (la )?suscripci[oó]n|cancelar suscripci[oó]n|administrar (sus |tus? )?preferencias|preferencias de (correo|email)|ya no desea recibir|dejar de recibir|ver (este )?correo en (su |el )?navegador|recibe este (correo|mensaje) porque)\b`,
  ),
  credentialAsk: compile(
    String.raw`\b(contrase[nñ]a|credenciales|verificar (su |tus? )?cuenta|iniciar sesi[oó]n para (verifi|confirma)|otp|c[oó]digo de (verificaci[oó]n|un solo uso))\b`,
  ),
  genericSalutation: compile(
    String.raw`\b(estimado\/?a? (cliente|usuario|miembro|titular)|estimado cliente|querido cliente|hola (cliente|usuario)|atenci[oó]n:? (cliente|usuario)|apreciado (cliente|usuario))\b`,
  ),
};
