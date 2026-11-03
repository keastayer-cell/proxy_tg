# Personal VLESS + REALITY

Independent service `proxy-xray.service`, TCP 2053 on 178.62.199.241. MTProxy 443 and SOCKS5 8443 remain separate and are not restarted by this deployment.

Official Xray release and SHA256 are pinned in `release.json`. The installer generates UUID, X25519 private/public keys and short ID once. Redeployment preserves them in root-only `/etc/proxy_tg/xray/credentials.json`. The service runs as a dedicated unprivileged user with read-only system access and resource limits; systemd enables startup and automatic recovery. Private and link credentials must never be committed.

Server configuration: `/etc/proxy_tg/xray/config.json` (root:proxy-xray, 0640). Client import URI: `/etc/proxy_tg/xray/iphone.vless` (root-only). Client profiles contain only the public key and access UUID. REALITY target/SNI: `www.microsoft.com:443`, Chrome fingerprint, VLESS Vision.

GitHub Actions `xray.yml` validates real generated profiles with the pinned Linux binary and deploys only Xray when `XRAY_DEPLOY_ENABLED=true`, using the existing pinned SSH host key and deployment key. Change only `xray/**`, `tests/test_xray.py`, and this workflow to avoid triggering other services' workflows.

On iPhone import the private VLESS URI in a compatible client. Disable the previous VPN, turn off Telegram's built-in proxy, enable the new client using the user's own VPS. For mobile validation disable Wi-Fi and confirm Telegram sends and receives actual messages over MegaFon. A successful external server probe alone does not establish that the iPhone path works.
