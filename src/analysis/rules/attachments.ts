/**
 * Attachment detectors. Two rules govern the file:
 *
 *  1. **Nothing is ever opened.** Only the filename string is inspected: no download, no read, no hash,
 *     no MIME sniff. Something that fetches attachments to inspect them is a delivery mechanism, not a
 *     scanner.
 *  2. **An extension is not a verdict.** A `.zip` is not malware. These detectors report what was
 *     observed and leave the weighting to the scoring layer.
 */
import { formatList } from '../../shared/text.js';
import type { SecuritySignal } from '../../shared/types.js';
import { hasDirectionControl, stripBidiAndInvisible } from '../../shared/unicode.js';
import type { AnalysisContext } from '../context.js';
import { signal } from './types.js';
import type { Detect } from './types.js';

/**
 * Extensions that execute code, or that Windows/macOS will run with a double-click. Grouped by how
 * direct the execution path is, which is what distinguishes them from archives.
 */
const EXECUTABLE_EXTENSIONS: ReadonlySet<string> = new Set([
  'exe', 'scr', 'com', 'pif', 'cpl', 'msi', 'msp', 'mst', 'msc',
  'bat', 'cmd', 'ps1', 'psm1', 'ps1xml', 'psc1', 'sh', 'bash', 'command',
  'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'jar', 'class',
  'reg', 'inf', 'scf', 'lnk', 'url', 'application', 'appref-ms', 'gadget',
  'dll', 'ocx', 'sys', 'drv', 'app', 'dmg', 'pkg', 'deb', 'rpm', 'apk',
  'chm', 'hlp', 'vb', 'vbscript', 'ws', 'ade', 'adp', 'mde', 'mdb', 'accdb', 'cer',
]);

/** Disk images: they mount, bypass mark-of-the-web, and hide their contents from mail scanners. */
const DISK_IMAGE_EXTENSIONS: ReadonlySet<string> = new Set([
  'iso', 'img', 'vhd', 'vhdx', 'vmdk', 'udf', 'cue', 'nrg',
]);

/** Archives: legitimate and extremely common, but they conceal what is inside. */
const ARCHIVE_EXTENSIONS: ReadonlySet<string> = new Set([
  'zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'z', 'cab', 'arj', 'lzh', 'ace', 'zipx',
]);

/** Office formats that can carry macros. */
const MACRO_CAPABLE_EXTENSIONS: ReadonlySet<string> = new Set([
  'docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppam', 'sldm', 'xls', 'xlt', 'doc',
  'dot', 'ppt', 'pot', 'xlsb',
]);

/**
 * Formats commonly used as the first stage of a malware chain.
 *
 * No `.xml` or `.xsl`. A double-clicked `.xml` opens as a data tree, not a page, and it is the format
 * structured invoices travel in (national e-invoicing schemes deliver every supplier invoice as one),
 * so listing it would report each of those as a web page and pair it with the word "invoice" into a
 * `critical`. What actually renders a page from a local file is the rest of this list.
 */
const SCRIPT_CONTAINER_EXTENSIONS: ReadonlySet<string> = new Set([
  'html', 'htm', 'xhtml', 'svg', 'mhtml', 'mht', 'shtml', 'one', 'wsz',
]);

/** Extensions a reader is likely to assume are safe, used as the *first* half of a double extension. */
const DECOY_EXTENSIONS: ReadonlySet<string> = new Set([
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'jpg', 'jpeg', 'png', 'gif',
  'csv', 'rtf', 'html', 'htm', 'mp4', 'mp3', 'zip', 'invoice', 'receipt', 'scan', 'statement',
]);

/** Every extension a rule below reports on, so the all-clear note cannot drift from the rules. */
const RISKY_EXTENSION_SETS: readonly ReadonlySet<string>[] = [
  EXECUTABLE_EXTENSIONS,
  DISK_IMAGE_EXTENSIONS,
  ARCHIVE_EXTENSIONS,
  MACRO_CAPABLE_EXTENSIONS,
  SCRIPT_CONTAINER_EXTENSIONS,
];

/** Directly executable attachments. */
function executableAttachments(context: AnalysisContext): SecuritySignal[] {
  const hits = context.attachments.filter((a) => EXECUTABLE_EXTENSIONS.has(a.extension));
  if (hits.length === 0) return [];
  const files = formatList(hits.map((h) => h.filename));

  return [
    signal({
      id: 'attachment.executable',
      category: 'attachment',
      severity: 'critical',
      score: 40,
      title: 'Attachment is a program rather than a document',
      description: `The message carries ${files}. Files of this type run code when opened. Legitimate correspondence does not deliver programs by email.`,
      evidence: { value: files },
    }),
  ];
}

/** Disk images, which sidestep the operating system's downloaded-file warnings. */
function diskImageAttachments(context: AnalysisContext): SecuritySignal[] {
  const hits = context.attachments.filter((a) => DISK_IMAGE_EXTENSIONS.has(a.extension));
  if (hits.length === 0) return [];
  const files = formatList(hits.map((h) => h.filename));

  return [
    signal({
      id: 'attachment.disk_image',
      category: 'attachment',
      severity: 'high',
      score: 28,
      title: 'Attachment is a disk image',
      description: `The message carries ${files}. Disk images mount as a drive and their contents do not inherit the operating system's "downloaded from the internet" warnings, which is why they are used to deliver executables.`,
      evidence: { value: files },
    }),
  ];
}

/**
 * Archives. Deliberately a *separate, lower* signal than executables: a ZIP is the single most
 * common legitimate attachment type there is. Severity rises only when the surrounding message also
 * looks like a lure.
 */
function archiveAttachments(context: AnalysisContext): SecuritySignal[] {
  const hits = context.attachments.filter((a) => ARCHIVE_EXTENSIONS.has(a.extension));
  if (hits.length === 0) return [];
  const files = formatList(hits.map((h) => h.filename));

  const passwordProtected = /\b(password|passcode|pin)\b[^.]{0,60}\b(attach|archive|zip|file|document|open)/u.test(
    context.matchText,
  ) || /\b(attach|archive|zip|file|document)\b[^.]{0,60}\bpassword\s*(is|:)/u.test(context.matchText);

  const luresPresent = context.claims.length > 0 || context.senderIsFreemail;

  return [
    signal({
      id: 'attachment.archive',
      category: 'attachment',
      severity: passwordProtected ? 'high' : luresPresent ? 'medium' : 'low',
      score: passwordProtected ? 26 : luresPresent ? 14 : 8,
      title: passwordProtected
        ? 'Password-protected archive attached'
        : 'Archive attachment present',
      description: passwordProtected
        ? `The message carries ${files} and supplies a password for it in the message text. A password stops mail-scanning systems from inspecting the contents, which is the reason to use one.`
        : `The message carries ${files}. Archives are common and usually harmless, but their contents cannot be seen without opening them.`,
      evidence: { value: files },
    }),
  ];
}

/** Macro-capable Office documents. */
function macroCapableAttachments(context: AnalysisContext): SecuritySignal[] {
  const hits = context.attachments.filter((a) => MACRO_CAPABLE_EXTENSIONS.has(a.extension));
  if (hits.length === 0) return [];
  const files = formatList(hits.map((h) => h.filename));
  const explicitlyMacro = hits.some((h) => h.extension.endsWith('m'));

  return [
    signal({
      id: 'attachment.macro_capable',
      category: 'attachment',
      severity: explicitlyMacro ? 'high' : 'low',
      score: explicitlyMacro ? 24 : 8,
      title: explicitlyMacro
        ? 'Attachment is a macro-enabled document'
        : 'Attachment uses a legacy Office format that can contain macros',
      description: explicitlyMacro
        ? `The message carries ${files}. This format exists specifically to carry embedded code, and the code runs if macros are enabled.`
        : `The message carries ${files}. Older Office formats can embed macros; modern equivalents (.docx, .xlsx) cannot.`,
      evidence: { value: files },
    }),
  ];
}

/** HTML and SVG attachments, which render as a page from a local file. */
function scriptContainerAttachments(context: AnalysisContext): SecuritySignal[] {
  const hits = context.attachments.filter((a) => SCRIPT_CONTAINER_EXTENSIONS.has(a.extension));
  if (hits.length === 0) return [];
  const files = formatList(hits.map((h) => h.filename));

  return [
    signal({
      id: 'attachment.script_container',
      category: 'attachment',
      severity: 'high',
      score: 26,
      title: 'Attachment is a web page rather than a document',
      description: `The message carries ${files}. Opening it renders a page from a local file, which is used to present a convincing sign-in form without hosting it anywhere that could be blocked or taken down.`,
      evidence: { value: files },
    }),
  ];
}

/**
 * `invoice.pdf.exe`: a real extension hidden behind a decoy one. The dangerous half is caught by
 * the rules above; this rule is about the *deception*, which is independently damning.
 */
function doubleExtensionAttachments(context: AnalysisContext): SecuritySignal[] {
  const hits = context.attachments.filter((a) => {
    if (!a.hasDoubleExtension) return false;
    const chain = a.extensionChain;
    const last = chain[chain.length - 1] ?? '';
    const previous = chain[chain.length - 2] ?? '';
    const lastIsDangerous =
      EXECUTABLE_EXTENSIONS.has(last) ||
      DISK_IMAGE_EXTENSIONS.has(last) ||
      SCRIPT_CONTAINER_EXTENSIONS.has(last);
    // `report.tar.gz` is not deception.
    const isKnownCompound = ARCHIVE_EXTENSIONS.has(last) && ARCHIVE_EXTENSIONS.has(previous);
    return lastIsDangerous && DECOY_EXTENSIONS.has(previous) && !isKnownCompound;
  });
  const [first] = hits;
  if (first === undefined) return [];
  const chain = first.extensionChain;

  return [
    signal({
      id: 'attachment.double_extension',
      category: 'attachment',
      severity: 'critical',
      score: 40,
      title: 'Attachment filename disguises its real type',
      description: `"${first.filename}" is presented as a .${chain[chain.length - 2] ?? ''} file but its actual type is .${chain[chain.length - 1] ?? ''}. The harmless-looking extension in the middle of the name is decoration.`,
      evidence: { value: first.filename },
    }),
  ];
}

/**
 * Characters in a filename that change how it reads: ones that reverse it, so `gnp.exe` renders as
 * `exe.png`, and ones that render as nothing, so `invoice.ex\u00ade` is an `.exe` no blocklist matches.
 *
 * Two findings rather than one, because only the first makes the screen lie about the type. A reversed
 * name shows the reader an extension that is not the file's: `critical`, whatever the type. A hidden
 * character shows the right letters with a gap nobody can see; it is evidence of an attempt to slip past
 * a filter, and when the type it hides is dangerous the executable rule says so at full weight already.
 */
function filenameSpoofingAttachments(context: AnalysisContext): SecuritySignal[] {
  const hits = context.attachments.filter((a) => a.hasBidiTrick);
  const reversed = hits.find((a) => hasDirectionControl(a.filename));
  if (reversed !== undefined) {
    return [
      signal({
        id: 'attachment.filename_direction_override',
        category: 'attachment',
        severity: 'critical',
        score: 40,
        title: 'Attachment filename contains text-direction override characters',
        description: `The filename contains invisible characters that reverse how part of it is displayed, so the extension shown on screen is not the real one. Its actual type is .${reversed.extension}. Stripped of the hidden characters the name is "${stripBidiAndInvisible(reversed.filename)}".`,
        evidence: { value: stripBidiAndInvisible(reversed.filename) },
      }),
    ];
  }

  const [hidden] = hits;
  if (hidden === undefined) return [];
  return [
    signal({
      id: 'attachment.filename_hidden_characters',
      category: 'attachment',
      severity: 'medium',
      score: 16,
      title: 'Attachment filename contains invisible characters',
      description: `The filename contains characters that take up no space on screen, so it reads normally while not matching the name a filter would look for. Its actual type is .${hidden.extension}. Stripped of the hidden characters the name is "${stripBidiAndInvisible(hidden.filename)}".`,
      evidence: { value: stripBidiAndInvisible(hidden.filename) },
    }),
  ];
}

/**
 * Emitted when there are attachments but none matched a risk rule, so the panel can state the
 * negative finding explicitly: "No suspicious attachment detected" is more useful than silence.
 */
function benignAttachmentsNote(context: AnalysisContext): SecuritySignal[] {
  if (context.attachments.length === 0) return [];
  const risky = context.attachments.some(
    (a) =>
      RISKY_EXTENSION_SETS.some((set) => set.has(a.extension)) ||
      a.hasDoubleExtension ||
      a.hasBidiTrick,
  );
  if (risky) return [];

  return [
    signal({
      id: 'attachment.none_suspicious',
      category: 'attachment',
      severity: 'info',
      score: 0,
      title: 'No suspicious attachment detected',
      description: `${context.attachments.length === 1 ? 'The attachment' : `All ${String(context.attachments.length)} attachments`} use file types that do not execute code. Note that attachment contents are never opened or downloaded by this extension; only the filenames were examined.`,
      evidence: { value: formatList(context.attachments.map((a) => a.filename)) },
    }),
  ];
}

const attachmentDetectors: Detect[] = [
  executableAttachments,
  diskImageAttachments,
  archiveAttachments,
  macroCapableAttachments,
  scriptContainerAttachments,
  doubleExtensionAttachments,
  filenameSpoofingAttachments,
  benignAttachmentsNote,
] as const;

export function detectAttachmentSignals(context: AnalysisContext): SecuritySignal[] {
  return attachmentDetectors.flatMap((detect) => detect(context));
}
