# Microsoft Azure Cosmos DB .NET SDK custom client-side encryption

This package uses `Microsoft.Data.Encryption.Cryptography` for the MDE
algorithm. Newtonsoft JSON processing remains the default. On .NET 8, supported
operations can opt into the Stream processor through the public request-property
contract:

```csharp
QueryRequestOptions options = new()
{
    Properties = new System.Collections.Generic.Dictionary<string, object>
    {
        ["encryption-json-processor"] = "Stream"
    }
};
```

`"Newtonsoft"` explicitly selects the default processor. Applications can also
call `UseStreamingJsonProcessingByDefault()` on a container returned by
`WithEncryptor()`, subject to the limitations below. The processor names are
strings; the implementation's processor enum is not public API.

## Compatibility and migration

- Subclasses compiled against `1.0.0-preview07` remain compatible. `Encryptor`
  and `DataEncryptionKey` have no new abstract key-access or buffer members.
- The `CosmosDataEncryptionKeyProvider(EncryptionKeyStoreProvider, TimeSpan?)`
  constructor remains supported and non-obsolete. Use the `Create` factories
  for `DekCacheOptions` and hybrid legacy/MDE provider configuration.
- Stream writes support MDE only. Readers accept valid historical legacy,
  current MDE, and plaintext documents when the required keys are available.
- Migration is application-controlled: read, modify, and write the item with
  MDE options. There is no automatic background data migration.
- Typed `CreateItemAsync`, `ReplaceItemAsync`, and `UpsertItemAsync` normalize a
  top-level `_ei` placeholder when it is `null`, or when it is an object with a
  missing or `null` `_ea`. Raw stream and transactional-batch write boundaries
  do not normalize existing `_ei`; remove an approved placeholder before using
  those boundaries.
- Reads treat absent or `null` `_ei`, and an `_ei` object with missing or `null`
  `_ea`, as plaintext. A malformed non-null `_ei` value or a present unknown
  algorithm fails explicitly. A decryption result is reported only after
  successful authenticated decryption.

## Stream scope, ownership, and formatting

`UseStreamingJsonProcessingByDefault()` affects only operations that consult the
container default. Typed encrypted Create/Replace/Upsert operations require a
per-call property override to select Stream. `ReadItemAsync<DecryptableItem>`
and typed change-feed processor callbacks retain their JObject-based paths.
Stream-mode `FeedIterator<DecryptableItem>` pages should be disposed through
`IAsyncDisposable` so lazy item buffers are released promptly.

SDK response content is treated as borrowed input and is not overwritten.
Transformed item, feed, and read-many responses expose owned output that is
disposed with the response. Change-feed stream callback data is callback-scoped:
do not retain it after the callback returns.

Unchanged plaintext stream responses can retain their original byte formatting.
Once encryption or decryption transforms JSON, the contract is semantic JSON
preservation, not preservation of whitespace, property order, or every numeric
lexeme. The Stream implementation does not promise zero-copy operation or a
workload-independent performance improvement.

## Transactional batches

A batch rejects overlapping mutation or execution before starting side effects.
The same batch object can be reused after an awaited execution completes.
Typed per-operation results preserve status, ETag, and retry metadata. This is
not a general concurrency guarantee; serialize access to each batch instance.
