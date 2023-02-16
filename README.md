

Deprecated: complete rewriten. moved to https://github.com/tateisu/SubwayTooterAppServerV2

This app receives event sent from Mastodon's WebPush REST API, then this app send it to my mobile app (Subway Tooter) via Firebase Cloud Messaging.

- Mastodon's WebPush REST API https://github.com/tootsuite/mastodon/pull/7445
- Subway Tooter https://github.com/tateisu/SubwayTooter

Currently payload decryption is not implemented because Subway Tooter does not requires it's content, just use event as notification check trigger. 

But if you want sample of payload decryption. see also
- https://gist.github.com/tateisu/685eab242549d9c9ffc85020f09a4b71

JWT verify sample
- https://gist.github.com/tateisu/18e9807dfb8779c247d6297bcf445686

VAPID for Web Push
- https://tools.ietf.org/html/draft-ietf-webpush-vapid-01#section-4
