package io.bluewallet.echalote

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ConsensusParseTest {
    private val microdescBody = """
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALJcqKBDfT41bLkkBvKSMuictvSQjwiV2GUBszYb0zgOZV2D6pfIM6/Z
5oMUXbxVU0qPxvM+80h3AIoMsmsDrl91AWIS1gMPE/kKtyGnA/WaX3RfwkWvYXZz
5Dwg1Hoh2L41yNxml6QlEWEEk+sGh899od1KMYH5WdanNq/4xBNrAgMBAAE=
-----END RSA PUBLIC KEY-----
ntor-onion-key NaEdxqudourIdG2Zhijv+9QSWS8iEsVq6NUExXah7GM
id ed25519 uZ0YqbYpBJ8Ts8lomKs8PRlxPFucUJFayt/pWGilkd0
""".trimIndent()

    private val microdescHeads = """
network-status-version 3 microdesc
vote-status consensus
consensus-method 35
valid-after 2026-08-07 07:00:00
fresh-until 2026-08-07 08:00:00
valid-until 2026-08-07 10:00:00
voting-delay 300 300
client-versions 0.4.8.0
server-versions 0.4.8.0
known-flags Authority BadExit Exit Fast Guard HSDir MiddleOnly NoEdConsensus Running Stable StaleDesc V2Dir Valid
r c0der AjUfyI0L8G9s3lRSZWZB5hGdvX4 2038-01-01 00:00:00 95.216.20.80 8080 0
a [2a01:4f9:2a:14af::2]:8080
m mkHw/LD1moosjemRD+GqSqXzzK1kOvK3ZwTsCPGJIFs
s Fast Guard Running Stable V2Dir Valid
v Tor 0.4.8.8
pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4
w Bandwidth=34000
r rome2 AjV5EbiC8ldnbnWwfs//WIXks0U 2038-01-01 00:00:00 185.146.232.243 9001 0
m bqFbVmdtoHQMXRA/w4KtTKXQ5J0otxAnqz+vcX7IWyY
s Exit Fast Running V2Dir Valid
v Tor 0.4.8.8
pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4
w Bandwidth=5800
directory-footer
""".trimIndent()

    @Test
    fun parsesOnionKeyNtorAndIdEd25519() {
        val body = ConsensusParser.parseMicrodescOrThrow(microdescBody).first()
        assertTrue(body.onionKey.isNotEmpty())
        assertEquals("NaEdxqudourIdG2Zhijv+9QSWS8iEsVq6NUExXah7GM", body.ntorOnionKey)
        assertEquals("uZ0YqbYpBJ8Ts8lomKs8PRlxPFucUJFayt/pWGilkd0", body.idEd25519)
    }

    @Test
    fun parsesRouterEntriesWithFlagsUsedForPathSelection() {
        val c = ConsensusParser.parseOrThrow(microdescHeads)
        assertEquals(2, c.microdescs.size)
        val middle = c.microdescs[0]
        assertEquals("c0der", middle.nickname)
        assertTrue(middle.flags.contains("Fast"))
        assertTrue(middle.flags.contains("Stable"))
        assertTrue(middle.flags.contains("V2Dir"))
        assertEquals("mkHw/LD1moosjemRD+GqSqXzzK1kOvK3ZwTsCPGJIFs", middle.microdesc)
        val exit = c.microdescs[1]
        assertTrue(exit.flags.contains("Exit"))
        assertFalse(exit.flags.contains("BadExit"))
    }

    @Test
    fun keepsARouterWhoseVLineIsOmitted() {
        val text = microdescHeads.replace(
            "directory-footer",
            """
            r gotorDe5 AjWaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2038-01-01 00:00:00 65.109.87.89 9001 0
            m ccccccccccccccccccccccccccccccccccccccccccc
            s Fast Running Stable V2Dir Valid
            pr Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Relay=1-4
            w Bandwidth=100
            directory-footer
            """.trimIndent(),
        )
        val c = ConsensusParser.parseOrThrow(text)
        assertEquals(3, c.microdescs.size)
        assertEquals("c0der", c.microdescs[0].nickname)
        assertEquals("rome2", c.microdescs[1].nickname)
        assertEquals("gotorDe5", c.microdescs[2].nickname)
        assertEquals("Tor 0.4.8.8", c.microdescs[0].version)
        assertEquals("Tor 0.4.8.8", c.microdescs[1].version)
        assertEquals(null, c.microdescs[2].version)
    }
}
