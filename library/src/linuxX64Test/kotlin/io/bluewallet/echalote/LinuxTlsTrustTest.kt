package io.bluewallet.echalote

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertFailsWith

class LinuxTlsTrustTest {
    @Test
    fun everyChainIsRejected() =
        runTest {
            assertFailsWith<TlsCertificateError> {
                verifyWebPkiChain(listOf(TlsTestCerts.VALID_LEAF, TlsTestCerts.TEST_CA), "echalote.test")
            }
            assertFailsWith<TlsCertificateError> { verifyWebPkiChain(listOf(TlsTestCerts.ROCKETX_LEAF), "api.rocketx.exchange") }
        }
}
