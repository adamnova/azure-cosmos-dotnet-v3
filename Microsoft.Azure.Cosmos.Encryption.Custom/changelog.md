Preview features are treated as a separate branch and will not be included in the official release until the feature is ready. Each preview release lists all the additional features that are enabled.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### <a name="1.1.0-preview01"/> [1.1.0-preview01](https://www.nuget.org/packages/Microsoft.Azure.Cosmos.Encryption.Custom/1.1.0-preview01) - Unreleased

#### Added
- Adds a `net8.0` target. Newtonsoft remains the default JSON processor. Supported .NET 8 operations can opt into Stream processing with `RequestOptions.Properties["encryption-json-processor"] = "Stream"` or, where the operation consults the container default, `UseStreamingJsonProcessingByDefault()`. Use the string `"Newtonsoft"` to select the default processor explicitly; the processor enum is internal.
- Adds `IAsyncDisposable` support for lazy stream-backed `DecryptableItem` values and their feed pages. Dispose each `FeedResponse<DecryptableItem>` through `IAsyncDisposable` to release skipped or unmaterialized items promptly.
- Adds `CosmosDataEncryptionKeyProvider.Initialize(Container)` as the synchronous container-binding counterpart to `InitializeAsync`.
- Adds optional distributed caching of wrapped DEK properties, proactive refresh, scoped cache keys, provider disposal, and release-visible cache failure diagnostics. Raw DEK material is never written to the distributed cache.
- Adds `DekCacheOptions` through the approved `CosmosDataEncryptionKeyProvider.Create(...)` factories. The published `CosmosDataEncryptionKeyProvider(EncryptionKeyStoreProvider, TimeSpan?)` constructor remains supported and non-obsolete; hybrid legacy/MDE configuration uses the three-argument `Create` factory.

#### Fixes
- Legacy AEAD authentication tags are compared without data-dependent short-circuiting.
- Current readers accept valid historical legacy, MDE, and plaintext documents when the required keys are available. Date-like strings and supported JSON values are preserved semantically across read-modify-write migration.
- Missing or `null` encryption metadata, and metadata with a missing or `null` algorithm, are treated as plaintext placeholders. Malformed non-null metadata, unknown algorithms, invalid type markers, empty ciphertext, and invalid structured plaintext fail explicitly without publishing partial output or labeling undecryptable content as decrypted.
- Typed encrypted `CreateItemAsync`, `ReplaceItemAsync`, and `UpsertItemAsync` normalize approved plaintext `_ei` placeholders (`null`, or an object with missing or `null` `_ea`) before writing current MDE metadata. Raw stream and transactional-batch write boundaries reject an existing top-level `_ei` instead of rewriting it implicitly.
- Stream response transformation preserves the borrowed SDK input and publishes a separate owned output only after successful decryption. Response disposal owns both the transformed output and the underlying SDK response. Change-feed stream outputs are callback-scoped and are disposed after the callback returns.
- Stream processing handles short reads, bounds incomplete-token growth, preserves pass-through escaped strings and supported numeric forms, and fails atomically on malformed or unsupported encrypted data.
- Transactional batches reject overlapping mutation or execution before side effects, support reuse after an awaited execution completes, and preserve typed per-operation status, ETag, and retry metadata.
- Distributed-cache refresh, invalidation, cancellation, and diagnostics behavior is hardened so stale raw keys and silent release-build failures are avoided.

#### Breaking changes
- None for the published `1.0.0-preview07` subclass contract. Existing custom `Encryptor` and `DataEncryptionKey` subclasses continue to work; this release adds no public abstract key-access or buffer members.

#### Updates
- Updates `Microsoft.Data.Encryption.Cryptography` to `2.0.0-pre015` and `System.Threading.Tasks.Extensions` to `4.6.3`.
- Removes the direct `Azure.Core` and unused `System.Text.RegularExpressions` package references.
- Replaces the unused `Microsoft.Extensions.Caching.Memory` reference with `Microsoft.Extensions.Caching.Abstractions` `3.1.7`, which supplies the `IDistributedCache` contract used by this package.

#### Notes
- Stream writes support only `MdeAeadAes256CbcHmac256Randomized`; legacy encryption is read-compatible but is not produced by Stream writes. Migration is application-controlled read-modify-write work; no background migration is performed.
- `UseStreamingJsonProcessingByDefault()` is not a container-wide guarantee. Typed encrypted Create/Replace/Upsert operations need a per-call `"Stream"` override, while `ReadItemAsync<DecryptableItem>` and typed change-feed processor callbacks retain JObject-based paths.
- Stream-mode lazy feed pages require prompt asynchronous disposal. Change-feed streams are valid only for the callback lifetime. Do not retain either beyond its documented owner.
- Plaintext stream responses that require no transformation can retain their original bytes. Transformed JSON is guaranteed semantically, not by whitespace or property ordering; Newtonsoft/typed paths may also canonicalize numeric formatting. No zero-copy or workload-independent speedup is guaranteed.
- Transactional batch instances support awaited sequential reuse, not general concurrent use.
- The optional distributed cache stores wrapped DEK properties only. Configure the cache with encryption in transit and at rest.

### <a name="1.0.0-preview07"/> [1.0.0-preview07](https://www.nuget.org/packages/Microsoft.Azure.Cosmos.Encryption.Custom/1.0.0-preview07) - 2024-06-12

#### Fixes 
- [#4546](https://github.com/Azure/azure-cosmos-dotnet-v3/pull/4546) Updates package reference Microsoft.Azure.Cosmos to version 3.41.0-preview and 3.40.0 for preview and stable version support.

### <a name="1.0.0-preview06"/> [1.0.0-preview06](https://www.nuget.org/packages/Microsoft.Azure.Cosmos.Encryption.Custom/1.0.0-preview06) - 2023-06-28

#### Fixes 
- [#3956](https://github.com/Azure/azure-cosmos-dotnet-v3/pull/3956) Updates package reference Microsoft.Azure.Cosmos to version 3.35.1-preview.

### <a name="1.0.0-preview05"/> [1.0.0-preview05](https://www.nuget.org/packages/Microsoft.Azure.Cosmos.Encryption.Custom/1.0.0-preview05) - 2023-04-27

#### Fixes 
- [#3809](https://github.com/Azure/azure-cosmos-dotnet-v3/pull/3809) Adds api FetchDataEncryptionKeyWithoutRawKeyAsync and FetchDataEncryptionKey to get DEK without and with raw key respectively.

### <a name="1.0.0-preview04"/> [1.0.0-preview04](https://www.nuget.org/packages/Microsoft.Azure.Cosmos.Encryption.Custom/1.0.0-preview04) - 2022-08-16

#### Fixes 
- [#3386](https://github.com/Azure/azure-cosmos-dotnet-v3/pull/3386) Fixes custom serializer issue with DataEncryptionKeyContainer operations.

### <a name="1.0.0-preview03"/> [1.0.0-preview03](https://www.nuget.org/packages/Microsoft.Azure.Cosmos.Encryption.Custom/1.0.0-preview03) - 2022-04-15
- [#3145](https://github.com/Azure/azure-cosmos-dotnet-v3/pull/3145) Adds dependency on latest Microsoft.Azure.Cosmos preview (3.26.0-preview).

### <a name="1.0.0-preview02"/> [1.0.0-preview02](https://www.nuget.org/packages/Microsoft.Azure.Cosmos.Encryption.Custom/1.0.0-preview02) - 2021-10-29

#### Fixes 
- [#2834](https://github.com/Azure/azure-cosmos-dotnet-v3/pull/2834) Adds fix for deserialization issue for invalid date type.


### <a name="1.0.0-preview"/> [1.0.0-preview](https://www.nuget.org/packages/Microsoft.Azure.Cosmos.Encryption.Custom/1.0.0-preview) - 2021-10-20
- First preview of custom client-side encryption feature. See https://aka.ms/CosmosClientEncryption for more information on client-side encryption support in Azure Cosmos DB.
