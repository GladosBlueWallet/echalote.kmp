# echalote.kmp

Kotlin Multiplatform port of [`@hazae41/echalote`](https://github.com/Overtorment/echalote) (Overtorment fork): a Tor client that bootstraps over **meek** and builds a 3-hop **exit circuit**.

Primary targets are **Android** and **iOS**. JVM and linuxX64 are extra.

The consumer-facing API matches the TypeScript library: `Echalote.createExitDialer()` then `dial(host, port)` returning a byte duplex (`stream.outer`).

Do **not** use the retired Azure meek endpoint (`meek.azureedge.net`). The default is Tor Browser’s CDN77 backend.

## Usage

```kotlin
val dialer = Echalote.createExitDialer(
    ExitDialerOptions(
        meekUrl = Echalote.DEFAULT_MEEK_URL, // https://1603026938.rsc.cdn77.org/
        extendTimeoutMs = 15_000,
        openTimeoutMs = 20_000,
        circuitAttempts = 3,
        circuitRace = 2,
    ),
)
val stream = dialer.dial("check.torproject.org", 443)
// stream.outer is a ByteDuplex of the RELAY_BEGIN stream
stream.close()
dialer.dispose()
```

Directory consensus/microdescriptors are fetched over **clearnet HTTP** (same as the original). The Tor link TLS to the guard runs in userspace over meek (`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, no root CA check; the leaf certificate DER is used for CERTS `sign_to_tls`).

## Coordinates

`org.bitcoin.kmp:echalote`

## Tests

```bash
./gradlew :library:jvmTest
```
