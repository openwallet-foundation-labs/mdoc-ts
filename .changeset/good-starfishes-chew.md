---
"@owf/mdoc": minor
---

feat: add new openid4vp session transcript calculation methods.

NOTE that this introduces breaking chnages since `calculateSessionTranscriptBytesForOid4VpDcApi` has been renamed to `calculateSessionTranscriptBytesForOid4VpDcApiDraft24`. The `calculateSessionTranscriptBytesForOid4VpDcApi` method is now used for the latest (draft29/1.0) session transcript structure.

In addtion, `calculateSessionTranscriptBytesForOid4Vp` has been renamed to `calculateSessionTranscriptBytesForOid4VpDraft18`. The `calculateSessionTranscriptBytesForOid4Vp` method is now used for the latest (draft29/1.0) session transcript structure.
