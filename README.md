This app receives event sent from Mastodon's WebPush REST API.
Then this app send it to my mobile app (Subway Tooter) via Firebase Cloud messaging.

Mastodon's WebPush REST API https://github.com/tootsuite/mastodon/pull/7445
Subway Tooter https://github.com/tateisu/SubwayTooter

Currently payload decryption is not implemented because Subway Tooter does not requires it's content, just use event as notification check trigger.
but if you want sample of payload decryptiom. see also
https://gist.github.com/tateisu/685eab242549d9c9ffc85020f09a4b71
