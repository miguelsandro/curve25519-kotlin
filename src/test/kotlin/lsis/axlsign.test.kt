package lsis

import lsis.AxlSign
import org.jetbrains.spek.api.Spek
import org.jetbrains.spek.api.dsl.describe
import org.jetbrains.spek.api.dsl.it
import org.junit.Assert.*
import org.junit.platform.runner.JUnitPlatform
import org.junit.runner.RunWith

@RunWith(JUnitPlatform::class)
class Curve25519Test: Spek({
    val axlsign = AxlSign()

    fun IntArray.toHex(): String {
        var s: String = ""
        val CHARS = arrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')
        for(i in 0..this.size-1) {
            val v = this[i]
            val char2 = CHARS[v and 0x0f]
            val char1 = CHARS[v shr 4 and 0x0f]
            s += "$char1$char2"
        }
        return s
    }

    fun String.toIntArray(): IntArray {
        val ca = this.toCharArray()
        val re = IntArray(ca.size)
        for(i in 0..ca.size-1) {
            re[i] = ca[i].toInt()
        }
        return re
    }

    describe("axlsign") {

        it("should generate keys") {
            val seed = axlsign.randomBytes(32)
            val keys = axlsign.generateKeyPair(seed)
            assertEquals(keys.privateKey.size, 32)
            assertEquals(keys.publicKey.size, 32)
        }

        it("should sign and verify") {
            val seed = axlsign.randomBytes(32)
            val keys = axlsign.generateKeyPair(seed)
            val msg = intArrayOf(1,2,3,4,5)
            val sig = axlsign.sign(keys.privateKey, msg, null)
            
            println("secret: " + keys.privateKey.toHex())
            println("public:" +  keys.publicKey.toHex())
            println("signat: " + sig.toHex())

            assertEquals(sig.size, 64)
            assertEquals(axlsign.verify(keys.publicKey, msg, sig),1)
        }

        it("should generate deterministic signatures if not randomized") {
            val seed = axlsign.randomBytes(32)
            val keys = axlsign.generateKeyPair(seed)
            val msg = intArrayOf(1, 2, 3, 4, 5)
            val sig1 = axlsign.sign(keys.privateKey, msg, null)
            val sig2 = axlsign.sign(keys.privateKey, msg, null)
            assertEquals(sig1.toHex(), sig2.toHex())
        }

        it("should generate different signatures if randomized") {
            val seed = axlsign.randomBytes(32)
            val keys = axlsign.generateKeyPair(seed)
            val msg = intArrayOf(1, 2, 3, 4, 5)
            val sig0 = axlsign.sign(keys.privateKey, msg, null) // not randomized
            val sig1 = axlsign.sign(keys.privateKey, msg, axlsign.randomBytes(64))
            val sig2 = axlsign.sign(keys.privateKey, msg, axlsign.randomBytes(64))

            assertNotEquals( sig1.toHex(), sig2.toHex() )
            assertNotEquals( sig0.toHex(), sig1.toHex() )
            assertNotEquals( sig0.toHex(), sig2.toHex() )
        }

        it("should sign (randomized) and verify") {
            val seed = axlsign.randomBytes(32)
            val random = axlsign.randomBytes(64)
            val keys = axlsign.generateKeyPair(seed)
            val msg = intArrayOf(1, 2, 3, 4, 5)
            val sig = axlsign.sign(keys.privateKey, msg, random)

            assertEquals(sig.size, 64)
            assertEquals(axlsign.verify(keys.publicKey, msg, sig), 1)
        }

        it("should not verify bad signature") {
            val seed = axlsign.randomBytes(32)
            val keys = axlsign.generateKeyPair(seed)
            val msg = intArrayOf(1, 2, 3, 4, 5)
            val sig = axlsign.sign(keys.privateKey, msg, null)

            assertEquals(axlsign.verify(keys.publicKey, msg, sig), 1)

            sig[0] = sig[0] xor sig[0]
            sig[1] = sig[1] xor sig[1]
            sig[2] = sig[2] xor sig[2]
            sig[3] = sig[3] xor sig[3]

            assertEquals(axlsign.verify(keys.publicKey, msg, sig), 0)
        }

        it("should not verify bad message") {
            val seed = axlsign.randomBytes(32)
            val keys = axlsign.generateKeyPair(seed)
            var msg = intArrayOf(1, 2, 3, 4, 5)
            val sig = axlsign.sign(keys.privateKey, msg, null)

            assertEquals(axlsign.verify(keys.publicKey, msg, sig), 1)

            msg = intArrayOf(1, 2, 3, 4)

            assertEquals(axlsign.verify(keys.publicKey, msg, sig), 0)
        }

        it("should signMessage and openMessage") {
            val seed = axlsign.randomBytes(32)
            val keys = axlsign.generateKeyPair(seed)
            val msg = "lo esencial es invisible a los ojos"
            val signedMsg = axlsign.signMessage(keys.privateKey, msg.toIntArray(), null)

            assertEquals(signedMsg.size, msg.length + 64) // *** R
            assertEquals(axlsign.openMessageStr(keys.publicKey, signedMsg), msg)
        }

        it("should calculate key agreement") {
            val seed1 = axlsign.randomBytes(32)
            val seed2 = axlsign.randomBytes(32)

            val k1 = axlsign.generateKeyPair(seed1)
            val k2 = axlsign.generateKeyPair(seed2)

            val sk1 = axlsign.sharedKey(k2.privateKey, k1.publicKey)
            val sk2 = axlsign.sharedKey(k1.privateKey, k2.publicKey)

            assertEquals(sk1.toHex(), sk2.toHex())
        }
    }

})
