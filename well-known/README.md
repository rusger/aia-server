# Universal / App Link Files for T2.B Partner Invites

These two files have to be served from the **canonical** locations on
`astrolytix.com` for iOS Universal Links and Android App Links to verify.

## File 1: `apple-app-site-association`

* **Location served from:** `https://astrolytix.com/.well-known/apple-app-site-association`
* **Content-Type:** `application/json`
* **No `.json` extension!** Apple is strict about this.
* **No HTTP redirects!** The 200 must come straight from the host.

The current content allowlists `/i/*` paths for the `com.astrolytix.app`
bundle under team `LUY77SVN7G`. Verify those values still match the
production iOS build before deploying.

## File 2: `assetlinks.json`

* **Location served from:** `https://astrolytix.com/.well-known/assetlinks.json`
* **Content-Type:** `application/json`

The `sha256_cert_fingerprints` field is currently a placeholder.
Replace it with the **Play App Signing** SHA-256 fingerprint that
Google Play uses for the Astrolytix app:

```
Google Play Console → Setup → App integrity → App signing key certificate
```

Copy the SHA-256 line and paste it into `assetlinks.json` (the format
is colon-separated hex like `AB:CD:EF:...`).

If the app is also distributed via APK / sideloaded builds you need to
list the upload key fingerprint in the same array.

## Nginx serving snippet

Add this inside the existing `server { ... }` block in
`etc-nginx-sites_enabled-astrologer` so the files are served with the
right Content-Type and no redirects:

```nginx
# T2.B universal/app link verification files
location = /.well-known/apple-app-site-association {
    default_type application/json;
    alias /var/www/html/.well-known/apple-app-site-association;
}

location = /.well-known/assetlinks.json {
    default_type application/json;
    alias /var/www/html/.well-known/assetlinks.json;
}
```

After deploying the file changes:

1. Copy both files into `/var/www/html/.well-known/` on the server.
2. `sudo nginx -t && sudo systemctl reload nginx`
3. Verify with curl:
   ```
   curl -i https://astrolytix.com/.well-known/apple-app-site-association
   curl -i https://astrolytix.com/.well-known/assetlinks.json
   ```
   Both should return `200 OK` with `Content-Type: application/json`.
4. iOS: trigger AASA refresh by deleting and re-installing the app.
5. Android: trigger app link verification by reinstalling and running
   `adb shell pm verify-app-links --re-verify com.astrolytix.app`.

## Optional: `/i/{hash}` fallback HTML page

When a recipient who does NOT have Astrolytix installed taps an invite
link, the OS falls back to opening the URL in a browser. Serving a small
landing page at `https://astrolytix.com/i/{hash}` with App Store +
Google Play badges turns those clicks into installs.

This is not implemented yet — add a `location /i/` block that proxies
to a tiny static or templated page when ready.
