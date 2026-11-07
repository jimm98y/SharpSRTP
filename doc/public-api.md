# Public API

What SharpSRTP exposes is written down, and a change to it does not build until it is written down
too. Two checks do this, both on every `dotnet build` of the library:

- **The API files.** `PublicAPI.Shipped.txt` and `PublicAPI.Unshipped.txt` in `src/SharpSRTP` list
  every public type and member that all four target frameworks share. What only some of them offer
  is in `src/SharpSRTP/PublicAPI/<framework>/`: the `ArraySegment` and `byte[]` overloads of
  netstandard2.0 and net481, and the `Span` overloads of net8.0 and net10.0. Shipped is the API as
  released; Unshipped is what changed since. A public symbol missing from them fails the build with
  RS0016, a listed one that is gone with RS0017.
- **Package validation.** The package being built is compared with the last release
  (`PackageValidationBaselineVersion` in `SharpSRTP.csproj`), and every binary or source breaking
  change fails the build with a CP error. It also compares the target frameworks with one another.

## Adding to the API

Build, and accept the RS0016 fix in the IDE ("Add to public API"), or from the command line:

```
dotnet format analyzers src/SharpSRTP/SharpSRTP.csproj --diagnostics RS0016 --severity warn
```

That writes into the `PublicAPI.Unshipped.txt` next to the project, which is right for anything
every framework has. A member inside `#if NET8_0_OR_GREATER` (or its `#else`) belongs in the
`PublicAPI.Unshipped.txt` of each framework it exists on instead; the RS0016 error says which
framework it was reported for.

## Removing or changing the API

RS0017 names what disappeared. Moving its line from Shipped to Unshipped with a `*REMOVED*` prefix
records the removal; a member whose signature changed is a removal of the old line and an addition
of the new one.

If package validation then reports a CP error, the change breaks code built against the last
release. When that is intended, record it:

```
dotnet build src/SharpSRTP/SharpSRTP.csproj -c Release -p:ApiCompatGenerateSuppressionFile=true
```

That rewrites `src/SharpSRTP/CompatibilitySuppressions.xml`. Say in the pull request what broke.

Validation runs as part of the build, because the build packs. `dotnet pack` on its own does not
rebuild and validates whatever binaries are already in `bin`.

## Releasing

1. Move every line of each `PublicAPI.Unshipped.txt`, the per-framework ones too, into the
   `PublicAPI.Shipped.txt` beside it, dropping the `*REMOVED*` lines together with the shipped
   lines they remove.
2. Once the release is on nuget.org, set `PackageValidationBaselineVersion` to it, and regenerate
   `CompatibilitySuppressions.xml` as above: what it excused against the old baseline is in the new
   one, and only the differences between the frameworks remain.

## What is recorded now

The baseline is 0.5.8. `CompatibilitySuppressions.xml` holds two kinds of entries:

- **The DTLS refactoring, against 0.5.8.** `DtlsClient`, `DtlsServer`, `DtlsSrtpClient` and
  `DtlsSrtpServer` no longer derive from BouncyCastle or take its types in their constructors (the
  BouncyCastle peers are `BcDtls*` now); `IDtlsPeer.DoHandshake` takes an `IDtlsRequest` and
  `IDtlsSrtpPeer.CreateSessionContext` an `IDtlsSecurityParameters`; and
  `DtlsHandshakeCompletedEventArgs` no longer carries BouncyCastle's `SecurityParameters`.
- **`BouncyCastleExtensions` is internal**, against 0.5.8. It was public and in no namespace, so it
  turned up in the global namespace of every program referencing SharpSRTP.
- **The frameworks against one another**, as 0.5.8 already was. netstandard2.0 has the
  `ArraySegment` and `byte[]` overloads, net8.0 the `Span` ones in their place, so a library built
  against the netstandard2.0 SharpSRTP cannot call these members when it runs on net8.0 or later.
