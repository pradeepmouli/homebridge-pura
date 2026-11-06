<img src="branding/icon.png" alt="Pura Logo" width="125" />

[![verified-by-homebridge](https://img.shields.io/badge/homebridge-verified-blueviolet?color=%23491F59&style=flat)](https://github.com/homebridge/homebridge/wiki/Verified-Plugins)

**A Homebridge plugin for Pura smart fragrance diffusers.**

By default this plugin exposes a single on/off switch per diffuser. It’s designed to be used with Pura’s away mode and scheduling features disabled, so HomeKit can act as the primary automation layer.

You can optionally enable:
- Intensity Control: fan-style accessory with Subtle/Medium/Strong intensity levels.
- Nightlight Control: supports on/off, Brightness (snapped to Pura's 10-step brightness levels), and color for compatible diffusers.
- Bay Control: a separate tile per fragrance bay, named after the scent in it.
- Auto-Alternate Control: a switch for Pura's Auto-alternate fragrances setting on multi-bay diffusers.

## Supported Diffusers
This plugin is designed for the following diffusers. Every model gets an on/off
control by default. Everything else is opt-in, see
[Configuration Options](#configuration-options).

| | Diffuser | Fragrance bays | Intensity control | Nightlight control |
|:--:|:--|:--:|:--|:--:|
| <img src="branding/pura-mini.png" alt="Pura Mini" width="100" /> | **Pura Mini** | 1 | Subtle / Medium / Strong | Yes |
| <img src="branding/pura-4.png" alt="Pura 4" width="100" /> | **Pura 4** | 2 | Subtle / Medium / Strong | Yes |
| <img src="branding/pura-plus.png" alt="Pura Plus" width="100" /> | **Pura Plus** | 2 | Subtle / Medium / Strong | No <sup>1</sup> |
| <img src="branding/pura-home.png" alt="Pura Home" width="100" /> | **Pura Home** | 2 | Subtle / Medium / Strong | Yes <sup>2</sup> |

<sup>1</sup> The Pura Plus has an ambient light, but the plugin does not expose it as a HomeKit
nightlight.

<sup>2</sup> The Pura Home has now been verified against physical hardware. It reports hardware
version major `35` (device version `wall_5`), which the plugin recognizes, so it is labeled
correctly in HomeKit and exposes on/off, intensity, and nightlight controls like the other
supported models.

Other Pura hardware that reports itself through the same API, including the Pura 3 and the Pura
Car, is picked up automatically and gets on/off and intensity control, but has not been verified
against a physical device.

## Installation

1. Install this plugin using: `npm install -g @homebridge-plugins/homebridge-pura`
2. Edit your `config.json` file (see sample config below)
3. Run Homebridge

## Requirements

- Homebridge `^1.8.0` or `^2.0.0`
- Node.js `^18.20.4 || ^20.18.0 || ^22.10.0 || ^24.13.0`

## Configuration

Add the following platform to your `config.json`:

```json
{
  "platforms": [
    {
      "name": "Pura Smart Diffuser",
      "platform": "PuraSmartDiffuser",
      "username": "your-pura-email@example.com",
      "password": "your-pura-password",
      "forceNightlightOff": false,
      "enableFanService": false,
      "enableNightlightAccessory": false,
      "enableBayControl": false,
      "enableAutoAlternate": false
    }
  ]
}
```

### Configuration Options

Just the right amount of flexibility for the control freak in all of us. Tinker responsibly, though.
Some changes may require recreating existing HomeKit scenes or automations for your Pura diffusers.

- **username**: Your Pura email - *required*
- **password**: Your Pura password - *required*
- **forceNightlightOff (Force Nightlight Off)**: No mood lighting, please. Pura normally syncs the nightlight with the diffuser. Turn this on to keep the nightlight off while the diffuser is running. (default: false)
- **enableFanService (Enable Intensity Control)**: Because “on” and “off” aren’t enough choices. Replaces the on/off switch with a fan control for choosing Subtle, Medium, or Strong intensity. On multi-bay diffusers, intensity changes apply across available bays to keep auto-alternate working as expected. (default: false)
- **enableBayControl (Enable Per-Bay Controls)**: For those who like to pick favorites. Gives each fragrance bay its own HomeKit control. With Intensity Control enabled, each bay appears as a fan; otherwise, it appears as a switch. On diffusers that only run one bay at a time, turning one bay on turns the other off. Bays are named after the scent in them, see [Bay Names](#bay-names). (default: false)
- **enableNightlightAccessory (Enable Nightlight Controls)**: Set the vibe along with the scent. Adds HomeKit controls for the nightlight, including On/Off, Brightness, and Color, on compatible diffusers. (default: false)
- **enableAutoAlternate (Enable Auto-Alternate Control)**: Can’t pick a favorite? Let Pura play referee. Adds a HomeKit switch for Pura’s Auto-Alternate setting on multi-bay diffusers. When on, Pura rotates between fragrance bays over time; when off, it sticks with the bay you choose. Either way, only one bay diffuses at a time. (default: false)

## Email-code and Apple / Google account sign-in (beta)

This fork tracks [the maintained Pura plugin](https://github.com/homebridge-plugins/homebridge-pura),
while retaining the `homebridge-pura` package name and accepting the original `PuraFragranceDiffuser`
platform alias. The maintained `PuraSmartDiffuser` alias is also accepted. Existing child-bridge
settings are retained when editing configuration in the custom UI. Upstream has changed control
layouts since 1.0.0; review the intensity/bay options before upgrading an existing installation.

Select **Email verification code (recommended)** in plugin settings, enter your existing Pura
account email and choose **Send sign-in code**. Enter the six-digit code from your email and choose
**Verify and connect**, then **Save** and restart only the Pura child bridge. This also works with
an Apple-created account when Pura supports email-code access for that email; confirm that the
expected diffusers appear after connecting. No Apple password or cookie copying is required.

The UI keeps the pending challenge in memory for up to ten minutes, permits five verification
attempts, and limits resend requests. Reopening the settings requires a new code. Codes and
challenge session IDs are never written to config.json or the persistent token store. Password
login remains available for existing configurations.

**Advanced: import an existing website session** retains the manual fallback: sign in on pura.com,
copy only the `__prt` cookie value from browser developer tools into the masked field and connect.
Never share that value or an email code in chat, logs, screenshots or config.json.

The plugin exchanges this opaque refresh credential at Pura's HTTPS refresh endpoint and renews
its one-hour tokens automatically. It does not decrypt the credential or depend on a particular
user ID. Revoked or expired refresh credentials require signing in and importing a new value.
Website tokens come directly from the fixed, certificate-validated Pura endpoint; their issuer,
audience, expiry and matching account subjects are checked. They are not validated using the
unrelated Cognito signing keys. Existing runtime sessions reject account changes until restart.

The **Experimental mobile OAuth callback** section retains the older PKCE option. Its
`pura://callback` handoff is unreliable when the Pura app opens instead; prefer the website flow.

Disable the separate `@homebridge-plugins/homebridge-pura` installation before running this fork;
both register the maintained platform alias and should not control the same account concurrently.
After connecting, **Save** and restart only the Pura child bridge. JSON configuration needs
`"authMethod": "oauth"`; it does not need a Pura or Apple password in that mode. A private refreshable
session lives at `<Homebridge storage>/pura-oauth/session.json` (directory 0700, file 0600). This file
is a credential: protect backups and never include it in bug reports. Mobile OAuth tokens are verified against
Pura's Cognito signing keys, issuer, client and nonce. Refresh-token rotation is persisted
atomically with a shared UI/runtime lock. A replacement account requires a child restart so cached
accessories cannot silently switch accounts. To disconnect, stop the Pura child, remove its private
session file, then leave it stopped or configure another login method.

Native API login methods identified on 2026-11-05: `password`, `authCode`, `otp` and `otpVerify`.
Email-code login uses `otp` to obtain a private `sessionId`, then `otpVerify` with email, code and
that session ID. A live code request succeeded; complete live verification remains a user step.

Maintainer verification on 2026-11-05: a real Apple login at pura.com produced tokens accepted by
the device inventory API. `POST https://user.trypura.io/v1/auth/refresh` with `{ "prt": "..." }`
issued fresh tokens, and a renewed token successfully read the inventory. No device settings were
changed. Automated tests exercise renewal, private persistence, account isolation and sanitized
failures with synthetic credentials. The website integration uses an undocumented vendor API.

### Installing this fork from GitHub

Use the Homebridge UI install-by-package/URL facility with a packaged GitHub release asset URL.
Release archives include compiled `dist` files and require no development tooling on the host.
Git source installation is also supported: `github:pradeepmouli/homebridge-pura#<tag-or-commit>`.
A source install runs the `prepare` build and therefore needs development dependencies; prefer the
release archive for small Homebridge hosts. Preserve the existing child-bridge configuration and
restart only its child after installation. Never reset or unpair the bridge to change login methods.

## Usage

By default, each diffuser appears as a single switch in HomeKit (e.g., "Living Room Diffuser").

If `enableFanService` is set to `true`, each diffuser uses intensity control mode instead, with RotationSpeed mapped to:
- Subtle: 30
- Medium: 50
- Strong: 100

For multi-bay diffusers, intensity changes from HomeKit are synced across available bays.

Switching accessory types will require recreating HomeKit scenes and automations for all Pura diffusers in this plugin.

If `enableNightlightAccessory` is set to `true`, compatible diffusers expose nightlight controls.

### Bay Control

With `enableBayControl` set to `true`, a multi-bay diffuser shows one tile per bay instead of one
tile for the diffuser. Each bay can be turned on and, with intensity control also enabled, set to
its own level.

A diffuser runs one bay at a time, so turning on a bay turns the other off. That is true whether or
not Auto-alternate is on: alternating means the device rotates between the bays over time, not that
both diffuse at once. Turning a bay on from HomeKit does not change the Auto-alternate setting.

A bay with no vial in it reads as off and refuses to turn on, with a note in the log saying why. A
bay whose fragrance Pura reports as spent still works, because the diffuser goes on running it.

### Bay Names

Bay tiles are named after the fragrance loaded in them, and follow a vial swap:

| Bays | Tile names |
| --- | --- |
| Different scents | `Volcano`, `Salt` |
| The same scent in both | `Bay 1: Volcano`, `Bay 2: Volcano` |
| One bay empty | `Volcano`, `Bay 2` |
| Both empty | `Bay 1`, `Bay 2` |

The bay number appears only when the scent alone would not tell the bays apart. That keeps voice
control exact where it can be: "turn on Volcano" matches the tile when the scents differ, and is
ambiguous anyway when they do not.

If you rename a bay tile yourself in the Home app, your name stays until the next time that bay's
fragrance changes, at which point the plugin renames it again. HomeKit does not tell a plugin that
a user has renamed something, so there is no way to detect and respect it. This is a consequence of
keeping names in step with what is loaded rather than a bug, and it only applies with
`enableBayControl` turned on.

### Controls

- **Power (default mode)**: Turn the diffuser on/off using the switch accessory
- **Intensity Control (optional mode)**: Use the fan-style accessory and set intensity to Subtle, Medium, or Strong
- **Bay Control (optional)**: Turn each fragrance bay on or off, and set its intensity, from its own tile
- **Nightlight Control (optional)**:
  - On/Off
  - Brightness (snapped to Pura's 10-step brightness levels)
  - Color (Hue/Saturation)

### Device Management

The plugin will automatically:
- Discover all Pura devices on your account
- Create one diffuser accessory per device:
  - Switch by default
  - Intensity control accessory when `enableFanService=true`
  - One tile per fragrance bay when `enableBayControl=true`
- Optionally add nightlight controls on compatible models when enabled
- Update device status via realtime updates with a 5-minute polling fallback (15s when realtime is down)
- Handle authentication and token refresh (including periodic Cognito refresh polling)

## Recommended Usage

- Use this plugin in lieu of Pura schedules or away mode.
- Enable **Auto-alternate fragrances** to spread wear evenly across both bays. With
  `enableAutoAlternate` you can toggle it from HomeKit instead of the Pura app.
- Turn on `enableBayControl` if you want to choose which scent is running. Leave it off to keep a
  single tile per diffuser.

## Troubleshooting

### Authentication Issues

If you encounter authentication errors:
1. Verify your username and password are correct
2. In Homebridge UI, click **Verify** before clicking **Save**
3. Check that your Pura account is active and can log in to the mobile app
4. Ensure your internet connection is stable

### Device Not Appearing

If your Pura device doesn't appear in HomeKit:
1. Check that the device is online and connected to WiFi
2. Verify it appears in the Pura mobile app
3. Check Homebridge logs for error messages
4. Try restarting Homebridge

### Connectivity Issues

If the plugin loses connection:
1. Check your internet connection
2. Verify Pura services are operational
3. Try restarting the plugin by restarting Homebridge

## Support

For issues and feature requests, please use the [GitHub Issues](https://github.com/homebridge-plugins/homebridge-pura/issues) page.

## Credits

This plugin is inspired by and based on the [pypura](https://github.com/natekspencer/pypura) Python library by @natekspencer.

## License

Apache-2.0
