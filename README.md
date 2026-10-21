# QuantumForge — Cloud Messaging Edition (global usernames + passkey sign-in)

Static site (HTML/CSS/JS, no build step). Usernames live in Supabase, so one username works on every device.
Sign-in uses a passkey: Face ID, Touch ID, Windows Hello, Android biometrics or fingerprint (the browser may offer
the device PIN when no biometric is set up; a website cannot force face-only).

## One-time setup
1. Supabase -> SQL Editor -> paste all of `schema.sql` -> Run (safe to re-run; it upgrades an existing `profiles` table).
2. Upload every file in this folder to the site root on EdgeOne (note the new `passkey-lib.js`).
3. Open the site over HTTPS. Passkeys are bound to the domain, so use one domain consistently (quantumforge2.edgeone.dev).

## How it works
- **Create username:** checks the cloud directory (case-insensitive, first come first served), creates a discoverable
  passkey (face/fingerprint), generates an RSA-2048 message key, and stores in `profiles`: public key, passkey public
  key, and an encrypted backup of the private key.
- **Sign in (any device):** tap *Sign in with passkey*; no username needed. The passkey names the account, the app verifies
  the passkey signature (challenge, origin, rpId, user-verification flag) against the key stored in the cloud, then restores
  your message key on that device if it is missing. On a new computer you can pick a synced passkey (iCloud Keychain,
  Google Password Manager, Windows) or use the phone that holds it.
- **Key backup protection:** if the passkey supports the WebAuthn PRF extension, the backup is encrypted with a secret only
  that passkey can produce, with nothing extra to remember. If not, you choose a recovery password (12+ chars,
  PBKDF2-600k + AES-GCM). That password cannot be reset.
- **Messages:** AES-256-GCM per message, key wrapped for recipient and sender with RSA-OAEP. Only ciphertext is stored.

## Limits
- Passkey verification happens in the browser (there is no server). It protects the UI and key restore, and message
  secrecy rests on the private key, but "From" is not cryptographic proof of identity: someone could insert a row claiming
  another sender. Real sender proof needs message signatures or server-side auth.
- The encrypted key backup and all message metadata are readable with the public key. A weak recovery password can be
  brute-forced offline, so use a long one (PRF-backed accounts do not have this weakness).
- Accounts created with the older passkey-only build (credentials kept only in one browser) have no cloud passkey; create a
  new username. Usernames and passkeys cannot be changed or deleted from the app (delete the row in Supabase to release one).
- If you lose both the passkey and the recovery password, old messages cannot be decrypted.
- The Boson Sampling visualization is illustrative and is not used to make keys.
