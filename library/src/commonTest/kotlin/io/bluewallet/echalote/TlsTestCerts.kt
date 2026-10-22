package io.bluewallet.echalote

/** DER fixtures for TLS certificate tests. Regenerate with library/src/jvmTest/resources/tls/generate.sh. */
internal object TlsTestCerts {
    /** Test leaf signed by the test CA: SAN DNS:echalote.test, DNS:*.wild.echalote.test, IP:127.0.0.1. */
    val VALID_LEAF: ByteArray by lazy {
        Base64.decode(
            "MIIDYjCCAkqgAwIBAgIJAOszwu5pFbaNMA0GCSqGSIb3DQEBCwUAMCAxHjAcBgNVBAMMFUVjaGFsb3RlIFRlc3QgUm" +
                "9vdCBDQTAgFw0yNjAxMDEwMDAwMDBaGA8yMTI1MTIzMTIzNTk1OVowEDEOMAwGA1UEAwwFdmFsaWQwggEiMA0GCSqG" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6wbG2ySrjGAWW4OCIjliLOz4bB37Ekh0kihM+8ho2ejWj6Iy9n6Y706KMoQ" +
                "LrpuBIZqVmyM7EtJWeo2r4+zTdEQZ5JOOub/q6EPmUC8rek15jJaSUUrLzLxGXMcvtqpdBSy1xeCHAwmcpaWP1lKOH" +
                "9AKJBGZ0LPDuDTL6/r6cPDgQBmGCAcCbT1yZuWFiqBJbKwI0rfbCjKOea3ZTOabiCLRGF8hd8WgCUvtiJM3kWIF92B" +
                "QPwysfnogH0X14CByfndC/JJLwdYJVqE9Wi2zdsSr3GDN+iAjHZEA74xF8L0q9ll5boU5JLm22IaLdVqXQ94CdZKAf" +
                "tIBwe0IsqYXtAgMBAAGjgawwgakwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQ" +
                "UHAwEwNAYDVR0RBC0wK4INZWNoYWxvdGUudGVzdIIUKi53aWxkLmVjaGFsb3RlLnRlc3SHBH8AAAEwHQYDVR0OBBYE" +
                "FNRUSFxbQ41qinif0bqBKlsp4dBFMB8GA1UdIwQYMBaAFCS3v8pj8Z6GZ8F5oyqntw0ERBaEMA0GCSqGSIb3DQEBCw" +
                "UAA4IBAQAOVJPiftwvoma0Y0XmmotdK+38AvN2xFdgUIUD6UiqZTtJhIpefij7IytxitNzIEkQQoLQ5EMYC0Z6IeLj" +
                "IwYg9qk6sBZuXnzuKO6d8hXs6nCtTB+8UShHA8YsWZ7oJW+E0PXZ+9pF0pWOK00+S5XY3v6VbNQvbqTwtM6ipeNkDa" +
                "RKYR7G2PgI0xqZuuQRvYTVuqULI9dv4MGYz7/8QchJX7vW1ml6umZ+icQwIGT7lj8eOI0cDZzuu1HJ4S1G15ZTCMs5" +
                "LaMd2qpjiZxv0E1q/3iksnhhbJpbNV0h+GkIhgpdssEUCD6+c4CH9N/hspgH2coFsUAZ1rPIIbbQAR27",
        )
    }

    /** Test root CA (no subjectAltName extension). */
    val TEST_CA: ByteArray by lazy {
        Base64.decode(
            "MIIDMzCCAhugAwIBAgIUX9ERasBUd+r6MpmfnV/Jjk0IY+owDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UEAwwVRWNoYW" +
                "xvdGUgVGVzdCBSb290IENBMCAXDTI2MDEwMTAwMDAwMFoYDzIxMjUxMjMxMjM1OTU5WjAgMR4wHAYDVQQDDBVFY2hh" +
                "bG90ZSBUZXN0IFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQXxEdvtQEE2yS7rWdOwKfer" +
                "kVpW4cvsk/xpbxyiuvDNrYJoRzj/Je2GqvfzC68MVKLE+EJmlXEbV0buUNV78YAUZnGXJMi9DyrxEANdM0vHZagYxQ" +
                "a2HPLvzWUR6FcWYu+KTGxm1CiXTsHl5O+N8iQznlDhM2wTTfhCLGbpyc/JN84/4oMArjXIbXP3+FJ6jpVxHwkBk1rq" +
                "4PlYC5PLICMHTZgdwQSsRuzZrj4AlKKpXfBbf6ztbyI8rtAGZED9Q8zUBnMpJrudMP4UPZWFp4utTBfLpAuzHH2CKz" +
                "qYjvoOtAzxBVRoGvG1l0rs7T29aDMui5FiV49G7NFrdfOi4XAgMBAAGjYzBhMB0GA1UdDgQWBBQkt7/KY/GehmfBea" +
                "Mqp7cNBEQWhDAfBgNVHSMEGDAWgBQkt7/KY/GehmfBeaMqp7cNBEQWhDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB" +
                "/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAZ0J6yNfRVsfU41tlOXu0SaZBRrzAmI006X7CWXG0qPyE2unFalXXu1" +
                "ey3o21Z0hamp3BO5q25hzyKWNeV+p2mLLyJKQMCcqOJ7uBy9aB9UR1BN3LK7mKuvnw0K00Es0DupdjB61hGyu+n3ZM" +
                "YfMBIOIM8GcfLkGold7T2dUZyfXZcdE5yMGe4R1EFnu9THIbNxAi6a6xmGIeTdwa4IBFhtz1hm6XQgd/appYKvla7N" +
                "8fvKrwxnZV4fk2u/A2a1c8BVdyDRiDwcgwgnLn5Luo+uDOvTrMcoqpYPfK0y6att/9e0PoPJgJlnwSFVnP2dWWDXFj" +
                "2s8r74Tw+n7IDl0Ykw==",
        )
    }

    /** Real api.rocketx.exchange RSA leaf captured 2026-10-22: SAN DNS:rocketx.exchange, DNS:*.rocketx.exchange. Only parsed, never time-checked. */
    val ROCKETX_LEAF: ByteArray by lazy {
        Base64.decode(
            "MIIFGDCCBACgAwIBAgIRAJ1TT06zPom2EzoH8UvqHqgwDQYJKoZIhvcNAQELBQAwOzELMAkGA1UEBhMCVVMxHjAcBg" +
                "NVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczEMMAoGA1UEAxMDV1IxMB4XDTI2MDkyNTA2NDg0N1oXDTI2MTIyNDA3" +
                "NDcxNVowGzEZMBcGA1UEAxMQcm9ja2V0eC5leGNoYW5nZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL" +
                "aHg6mIvJDYy3f/fYSujpTT9NKV7FlUnLvFKkSoRNrTQksy4gOeQ89EVT95CLEHKCTMsbKbXdjFqak2F0A5HBFv21/7" +
                "kqx84WyoIthPzhJcjZun7KPYGziXEzpuE9hbkXUAVW6XrOupXDgzAQmzabv1Ovo1H24tbYTkgjR5TTPuQ3i++h+r8s" +
                "riRORmGlmS0TBK+6gbReXOFmaxRdLN55dlJ6Z9xQkLWrFPPsFO9XquoBOgn93dkCvnHcYSnbWA7w57a8xlISiSgMzE" +
                "cIwB89iGveAnW8PpBW8IKcs8pVi/JSRBwhpYWVek9sOaf3RQyPiJNZvGxALhZJNr9xskJekCAwEAAaOCAjUwggIxMA" +
                "4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQVWX0Kzfgv" +
                "pqmt3E9RAiwxvNyLZDAfBgNVHSMEGDAWgBRmaUnU3iqckQPPiQ4kuA4wA26ILjA1BggrBgEFBQcBAQQpMCcwJQYIKw" +
                "YBBQUHMAKGGWh0dHA6Ly9pLnBraS5nb29nL3dyMS5jcnQwLwYDVR0RBCgwJoIQcm9ja2V0eC5leGNoYW5nZYISKi5y" +
                "b2NrZXR4LmV4Y2hhbmdlMBMGA1UdIAQMMAowCAYGZ4EMAQIBMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jLnBraS" +
                "5nb29nL3dyMS9iWTZET2ZXMUJwMC5jcmwwggEFBgorBgEEAdZ5AgQCBIH2BIHzAPEAdwDCMX5XRRmjRe5/ON6ykEHr" +
                "x8IhWiK/f9W1rXaa2Q5SzQAAAaDXic/LAAAEAwBIMEYCIQDQX7TaItEJ48UhMB3yBXBUT/cOvz4ivIwNxq4Lc/wjUA" +
                "IhAOOIqBqwErieOxMo2BAxwKT88dFk7/gKMluAq8DddXKkAHYA2AlVO5RPev/IFhlvlE+Fq7D4/F6HVSYPFdEucrtF" +
                "SxQAAAGg14nP6gAABAMARzBFAiAfm+zUZzvazvn3mUBt6rvgQNmhQnvn7uR9pNIRfQ36lQIhANPs8l2u2E0aERMwmx" +
                "mwMstGB8cty+MUMudZ5xKKV3ZEMA0GCSqGSIb3DQEBCwUAA4IBAQCvTRvy4G9PwQAIpP3iYpvczIhCx0iBk2C0ufkN" +
                "wSF0xqCQqTh1nMkU4W5zNKcEGdnM1pRTDkG+e4sMu6iusxSczYGTi8N7HEW5ltYbmnIp1T+f0b0nH7jCx1ma3I8ETQ" +
                "tW91Br66odsuQzdcNshVxjJSYk3u6SjMV55SELqyLyYeMVyq8W15d5YemRHc33NVXTO7ltp7/6ckLleBoWm2kW9dxk" +
                "kGjnBVIA0WHnLj6yQTubSA04yyGtRlUYwcmDxJnJpafm5U9VNNhkx3cnQuDHY2UY5aCyTe6cP+SGPRTsiQBNFjQKfG" +
                "Z4CDF+pWw2R1QEweQI++eHTMk/RyKK/cCV",
        )
    }
}
