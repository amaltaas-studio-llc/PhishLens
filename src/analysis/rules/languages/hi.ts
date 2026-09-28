/**
 * Hindi (Devanagari) wording pack.
 *
 * Gated by Devanagari letter share rather than function-word markers: short function words are hard
 * to list exhaustively across Hindi morphology, and the script itself is a reliable signal that the
 * pack should run. Patterns cover KYC updates, account blocking, OTP/UPI PIN solicitation and the
 * common urgency framing of Indian scam mail.
 */
import { compile, type LanguagePack } from './lexicon.js';

export const hi: LanguagePack = {
  id: 'hi',
  label: 'Hindi',
  script: 'devanagari',
  // Markers are unused for gating (script share decides), but kept as a small set for tests.
  markers: ['और', 'का', 'की', 'के', 'है', 'में', 'से', 'को', 'पर', 'यह', 'वह', 'आप', 'नहीं', 'लिए'],
  themes: {
    urgency: [
      compile(String.raw`\b(तुरंत|फौरन|अभी|जल्दी|बिना देरी|अविलंब)\b`),
      compile(String.raw`\b(\d{1,2} (मिनट|घंट[ेा]|दिन) (में|के अंदर))\b`),
      compile(String.raw`\b(अंतिम (चेतावनी|सूचना|अवसर)|समय सीमा|समाप्त हो|अभी कार्रवाई)\b`),
    ],
    credential_verification: [
      compile(
        String.raw`\b(सत्यापित|पुष्टि|अपडेट|अपडेट करें|अपडेट कीजिए|पूर्ण करें)\b[^.!?]{0,40}\b(अपना |अपनी )?(खाता|अकाउंट|केवायसी|kyc|पासवर्ड|पहचान|लॉगिन)\b`,
      ),
      compile(String.raw`\b(केवायसी|kyc)\b[^.!?]{0,30}\b(अपडेट|पूर्ण|पूरा|सत्यापन)\b`),
      compile(String.raw`\b(लॉगिन|साइन इन|साइन-इन) करें\b[^.!?]{0,40}\b(सत्यापित|पुष्टि|जारी|अनब्लॉक|पुनर्स्थापित)\b`),
      compile(String.raw`\b(आधार|पैन|pan)\b[^.!?]{0,40}\b(लिंक|अपडेट|सत्यापन|वेरिफाई)\b`),
    ],
    password_reset_pressure: [
      compile(String.raw`\b(पासवर्ड|कूटशब्द)\b[^.!?]{0,30}\b(रीसेट|बदल|समाप्त|एक्सपायर|अपडेट)\b`),
      compile(String.raw`\b(पासवर्ड|कूटशब्द) (रीसेट|बदल|अपडेट) करें\b`),
    ],
    account_threat: [
      compile(
        String.raw`\b(खाता|अकाउंट|एक्सेस|प्रोफ़ाइल)\b[^.!?]{0,40}\b(ब्लॉक|सस्पेंड|बंद|निष्क्रिय|हटा|प्रतिबंधित|लॉक)\b`,
      ),
      compile(String.raw`\b(संदिग्ध|असामान्य|अनधिकृत) (गतिविधि|लॉगिन|एक्सेस|साइन इन)\b`),
      compile(String.raw`\b(ब्लॉक|सस्पेंड|बंद|निष्क्रिय) (हो जाएगा|हो जायेगा|कर दिया जाएगा|कर दिया जायेगा)\b`),
    ],
    mfa_request: [
      compile(
        String.raw`\b(भेजें|बताएं|बताइए|शेयर करें|साझा करें|दें|प्रदान करें)\b[^.!?]{0,40}\b(ओटीपी|otp|सत्यापन कोड|सुरक्षा कोड|यूपीआई पिन|upi pin|पिन)\b`,
      ),
      compile(
        String.raw`\b(ओटीपी|otp|यूपीआई पिन|upi pin)\b[^.!?]{0,40}\b(भेजें|बताएं|बताइए|शेयर|साझा|दें)\b`,
      ),
      compile(String.raw`\bइस (ईमेल|मेल) का जवाब\b[^.!?]{0,40}\b(ओटीपी|otp|कोड|पिन)\b`),
    ],
    wire_transfer: [
      compile(String.raw`\b(पैसे|राशि|धन|फंड)\b[^.!?]{0,40}\b(ट्रांसफर|भेजें|भेजिए|ट्रांसफर करें)\b`),
      compile(String.raw`\b(बैंक ट्रांसफर|वायर ट्रांसफर|यूपीआई|upi) (करें|भेजें)\b`),
    ],
    payment_detail_change: [
      compile(
        String.raw`\b(अपडेट|बदल|नया|नई)\b[^.!?]{0,40}\b(बैंक (विवरण|डिटेल्स|खाता)|भुगतान (विवरण|डिटेल्स)|खाता संख्या)\b`,
      ),
    ],
    gift_card: [
      compile(String.raw`\b(खरीदें|खरीदिए)\b[^.!?]{0,40}\b(गिफ्ट कार्ड|गिफ्टकार्ड|प्रीपेड कार्ड|amazon|अमेज़न)\b`),
      compile(String.raw`\b(कोड|पिन)\b[^.!?]{0,40}\b(भेजें|शेयर|फोटो)\b`),
    ],
    secrecy: [
      compile(String.raw`\b(गोपनीय|गुप्त|किसी को मत बताना|किसी को न बताएं|केवल हमारे बीच)\b`),
      compile(String.raw`\b(किसी और को|किसी को भी) (नहीं|मत) (बताना|बताएं|बताइए)\b`),
    ],
    process_bypass: [
      compile(String.raw`\b(बिना|छोड़कर|नज़रअंदाज़)\b[^.!?]{0,40}\b(मंजूरी|अनुमोदन|सत्यापन|प्रक्रिया|सामान्य)\b`),
      compile(String.raw`\b(कॉल|फ़ोन|फोन) (नहीं|न) (ले|ले पाएंगे|कर सकते)\b`),
    ],
    prize_lure: [
      compile(String.raw`\b(आपने जीत|बधाई|चयनित)\b[^.!?]{0,50}\b(इनाम|लॉटरी|पुरस्कार|राशि)\b`),
      compile(String.raw`\b(रिफंड|मुआवजा|विरासत)\b[^.!?]{0,40}\b(बाकी|अप्राप्त|मंजूर|उपलब्ध)\b`),
    ],
  },
  negation: {
    before: compile(
      String.raw`\b(कभी नहीं|कभी न|मत|नहीं|न)\b(?:[^.!?,;]{0,40}\b(?:मांग|मांगते|पूछ|पूछते)\b)?\s{1,3}$`,
    ),
    after: compile(String.raw`^\s{0,40}\b(कभी नहीं|किसी को नहीं|किसी को मत|न करें|नहीं)\b`),
    conditional: compile(String.raw`\b(अगर|यदि|जब तक)\b[^.!?]{0,40}\b(नहीं|न|मत)\b`),
  },
  bulk: compile(
    String.raw`\b(अनसब्सक्राइब|सदस्यता रद्द|ईमेल प्राथमिकता|प्राथमिकताएं प्रबंधित|अब प्राप्त नहीं|यह ईमेल इसलिए|ब्राउज़र में देखें)\b`,
  ),
  credentialAsk: compile(
    String.raw`\b(पासवर्ड|क्रेडेंशियल|खाता सत्यापित|ओटीपी|otp|केवायसी|kyc|यूपीआई पिन|upi pin)\b`,
  ),
  genericSalutation: compile(
    String.raw`\b(प्रिय (ग्राहक|उपयोगकर्ता|सदस्य)|आदरणीय (ग्राहक|उपयोगकर्ता)|नमस्ते (ग्राहक|उपयोगकर्ता))\b`,
  ),
};
