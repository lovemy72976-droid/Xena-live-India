# Xena Live India — Play Store release checklist

## Included in this package
- Android app targeting API 36.
- Release AAB GitHub Actions workflow with secure keystore secrets.
- Real server login with JWT/bcrypt.
- Live room creation/end and Socket.IO chat/presence.
- WebRTC camera/microphone streaming with optional TURN configuration.
- Server-side coins/diamonds and gift ledger.
- Google Play Billing 9.1.0 client integration and server verification endpoint.
- Report/block controls, account deletion endpoint/page, privacy policy, terms and community guidelines.
- HTTPS-only Android WebView configuration.
- Helmet and basic HTTP rate limiting.

## Required before public launch
1. Deploy `server/` on a stable HTTPS Node.js host.
2. Use persistent production storage/database. The bundled JSON file is for testing/small deployments; it is not a durable production database on ephemeral hosting.
3. Configure `JWT_SECRET` to a long random secret.
4. Configure a TURN server with `TURN_URL`, `TURN_USERNAME`, and `TURN_CREDENTIAL`. STUN alone is not reliable for every mobile network.
5. Configure Google Play Billing products in Play Console: `coins_100`, `coins_500`, `coins_1000`, `coins_5000`.
6. Create a Google service account with Google Play Developer API access, grant it the minimum required Play Console permissions, and set `GOOGLE_PLAY_SERVICE_ACCOUNT_JSON` on the server. Never put this JSON in the Android app or GitHub repository.
7. Set `ANDROID_PACKAGE_NAME=com.xenalive.india` unless you change the application ID.
8. Replace the placeholder support email/domain in the legal pages.
9. Review the privacy policy, terms, community guidelines, data-retention language and age/content rules with your own legal/support details.
10. Create the Play Console app and complete the Data Safety, content rating, app access, ads declaration (if applicable), target audience and store listing forms.
11. Create a production signing keystore and keep it backed up securely. Do not commit the keystore.
12. Add these GitHub Actions secrets:
    - `ANDROID_KEYSTORE_BASE64`
    - `ANDROID_KEYSTORE_PASSWORD`
    - `ANDROID_KEY_ALIAS`
    - `ANDROID_KEY_PASSWORD`
13. Add GitHub Actions variable `XENA_SERVER_URL` with the exact HTTPS server URL ending in `/app`.
14. Run `Build Android Release`. The signed AAB is produced only when the signing secrets exist.
15. Test the signed AAB through Play Console internal/closed testing before production.

## Important policy/technical notes
- Virtual currency/digital goods sold in the Android app must follow Google Play's billing rules. The server must verify purchase tokens before crediting coins.
- Live/chat user-generated content needs accessible report and block functionality and active moderation.
- The current WebRTC architecture is intended for small rooms. For large rooms, replace the peer-to-peer fan-out with a production media server such as LiveKit or another SFU.
- Do not publish the placeholder legal contact details.
