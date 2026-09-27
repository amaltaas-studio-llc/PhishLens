# PhishLens

### A second look before you click.

**Spot signs of phishing in Gmail, with explanations you can check for yourself.**

PhishLens is a free, open-source Chrome extension that adds a risk badge to the email you're reading.
Click it to see what looks unusual, why it matters, and the evidence behind the score.
Analysis runs on your computer by default. No PhishLens account or API key is required.

**[Download PhishLens](https://github.com/nilayk/PhishLens/releases/latest)** ·
[Installation](#install) · [Privacy](#your-mail-stays-yours) ·
[Get help](https://github.com/nilayk/PhishLens/issues)

[![Latest release](https://img.shields.io/github/v/release/nilayk/PhishLens)](https://github.com/nilayk/PhishLens/releases/latest)
[![Licence: MIT](https://img.shields.io/badge/Licence-MIT-blue.svg)](LICENSE)

![PhishLens showing a High Risk badge beside a sender and an explanation of a lookalike domain and a misleading link.](docs/assets/in-message.png)

## See what deserves a closer look

A familiar name can hide an unfamiliar address. A convincing link can lead somewhere else.
PhishLens brings those details into view while you read.

- **Check the sender.** Find lookalike domains, misleading display names, and replies that imitate someone already in a conversation.
- **Understand the links.** See when a link's visible text and destination disagree, or a trusted name is buried in an unrelated address.
- **Notice risky requests.** Get findings about requests for verification codes, payment changes, gift cards, and pressure to act quickly.
- **Inspect attachment names.** Flag executable files and disguised extensions without opening or downloading them.
- **Read the reasons.** Open the badge for individual findings and a score breakdown. Hover over supported findings to highlight the relevant part of the message.

PhishLens is a reading aid. It does not block links, downloads, or replies, and a low score does not guarantee that a message is safe.

## Install

**For Gmail in desktop Chrome 120 or later.** PhishLens does not run in the Gmail mobile apps or other email clients.

Download the packaged extension from GitHub and load it into Chrome:

1. Open the **[latest release](https://github.com/nilayk/PhishLens/releases/latest)** and download `phishlens-<version>.zip` under **Assets**. Choose the extension ZIP, not GitHub's **Source code** downloads.
2. Unzip it into a folder you'll keep on your computer.
3. Enter `chrome://extensions` in Chrome's address bar and turn on **Developer mode**.
4. Click **Load unpacked** and select the extracted folder containing `manifest.json`.
5. Open or refresh Gmail, then open a received message. Look for the badge beside the sender.

No model setup is needed to use the core checks. Pin PhishLens from Chrome's Extensions menu for quick access to its status and settings.

**Updating a manual installation:** download and extract the newer release into the same extension folder, then click **Reload** on PhishLens at `chrome://extensions` and refresh Gmail. Manual installations do not update automatically from GitHub.

Want to build the current source yourself? Follow the [development guide](docs/DEVELOPMENT.md). Published downloads can lag behind the source on this page; check the [release notes](https://github.com/nilayk/PhishLens/releases) for the version you install.

## What the badge means

The score summarises the evidence PhishLens found. It is not a percentage chance that the message is phishing.

| Badge | Score | How to read it |
| --- | --- | --- |
| **Low Risk** | 0–24 | Few or no warning signs were found in the available evidence. This is not an all-clear. |
| **Caution** | 25–49 | Some details deserve a closer look. Open the badge to see why. |
| **Suspicious** | 50–74 | Significant warning signs were found. Verify the request through a known contact or website before acting. |
| **High Risk** | 75–100 | Strong warning signs were found. Avoid using the message's links or attachments to follow up. |
| **Not checked** | — | PhishLens could not read enough to assess the message. This is not a judgement of safety. |

![The badge beside four senders: Low Risk 12/100, Suspicious 50/100, High Risk 75/100, and a dashed grey Not checked badge on a message whose sender could not be read.](docs/assets/badges.png)

The explanation card separates observed findings from any optional AI assessment and supports light and dark mode.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/card-dark.png">
  <img src="docs/assets/card-light.png" width="400" alt="The PhishLens explanation card with a risk score and individual findings showing the evidence behind it.">
</picture>

## Your mail stays yours

An extension that reads email should be clear about what it does with it.

- **No uploads by default.** PhishLens analyses messages in the browser without making network requests in its default configuration.
- **No account, analytics, or telemetry.** There is no PhishLens service collecting your reading activity.
- **No saved email archive.** Message content is not written to persistent storage. Analysis results may remain in memory until the tab closes. Your settings and any addresses or domains you choose to trust are saved using Chrome's storage.
- **No opening message content.** PhishLens does not visit links, fetch images, or open attachments to inspect them. These checks use the text and filenames Gmail exposes.
- **Limited access.** Installation grants access to Gmail and storage for settings. An optional model-server connection requires separate permission for the address you configure.

**If you choose a model server**, PhishLens sends the sender's display name, subject, and a body excerpt to that server. A remote server receives that content over the network; this is an explicit setting, not the default.

[Read the full privacy and security details →](docs/PRIVACY.md)

## Make it work for you

Open **PhishLens in the Chrome toolbar → Settings** to adjust its behaviour.

**Keep the inbox quieter.** You can hide low-risk badges or turn on optional sender warnings in the message list. List warnings check sender identity only; an unmarked row has not been fully assessed.

![An inbox list where most rows are unmarked and a few carry a small warning beside the subject.](docs/assets/inbox-list.png)

**Manage trusted senders.** For eligible messages, the explanation card lets you trust an address or domain. Trust can soften some findings when Gmail verifies the sender, but it does not remove findings or silence high-severity warnings. You can undo it from the card or settings.

**Use optional AI.** Where Chrome makes an on-device model available, it can add an assessment of the wording. The core checks work without it. AI cannot remove their findings or raise the score without supporting evidence from those checks. Advanced users can connect their own model server. [AI availability and setup →](docs/LOCAL-AI.md)

## Help and limitations

**No badge?** Refresh Gmail after installing and open a received message. Your own outgoing replies are not assessed, and low-risk badges may be hidden by your settings. Click the toolbar icon to check the current status.

**Seeing "Not checked", or a result that seems wrong?** The toolbar and explanation card can provide diagnostic information. [Report a problem](https://github.com/nilayk/PhishLens/issues), including your extension version and what you expected. Review anything you share and remove private email content, addresses, links, and screenshots of personal correspondence.

PhishLens can miss phishing and can flag legitimate mail. It relies on what Gmail displays, so changes to Gmail's layout can affect extraction. Wording checks focus on English; sender, link, and filename checks can still help with other languages. It does not scan attachment contents or use live website-reputation services.

## Open source

This repository contains the source code for PhishLens. You can inspect how it works, build it yourself, report issues, or contribute improvements.

[How detection works](docs/DETECTION.md) · [Build and contribute](docs/DEVELOPMENT.md) ·
[Architecture](docs/ARCHITECTURE.md) · [Release history](https://github.com/nilayk/PhishLens/releases)

For code contributions, run `npm run verify` before opening a pull request. Use fictional examples in tests and reports rather than publishing anyone's private mail.

## Licence

PhishLens is free and open source under the [MIT licence](LICENSE).
It is an independent project and is not affiliated with or endorsed by Google.
