package lsis
 
import lsis.AxlSign

var axlsign = AxlSign()
var seed = axlsign.randomBytes(32);
var random = axlsign.randomBytes(64);
var keys = axlsign.generateKeyPair(seed);
var msg = IntArray(256)
var sig = axlsign.sign(keys.privateKey, msg, null);

class Result(_iterations: Int, _msPerOp: Double, _opsPerSecond: Double) {
    var iterations = _iterations
    var msPerOp = _msPerOp
    var opsPerSecond = _opsPerSecond
}

fun String.toIntArray(): IntArray {
	var ca = this.toCharArray()
	var re = IntArray(ca.size)
	for(i in 0..ca.size-1) {
		re[i] = ca[i].toInt()
	}	
	return re
}

fun IntArray.toHex(): String {
	var s: String = ""
	val CHARS = arrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')
	for(i in 0..this.size-1) {
		val v = this[i].toInt()
		val char2 = CHARS[v and 0x0f]
		val char1 = CHARS[v shr 4 and 0x0f]
    	s += "$char1$char2"
	}
	return s
}

fun IntArray.debug(): String {
    var sum = 0
    var s: String = ""
	for(i in 0..this.size-1) {
        sum += this[i]
		s += this[i].toString() + " "
	}
    s += " [sum: $sum]\n"
    return s
}

// Helper functions for benchmarking.

fun benchmark(fn: () -> Unit): Result {
  var elapsed = 0.0
  var iterations = 1
  while (true) {
    var startTime = System.currentTimeMillis()
    fn()
    elapsed += System.currentTimeMillis() - startTime;
    if ( ( elapsed > 500 ) or ( iterations > 2 ) ) {
      break
    }
    iterations++
  }
  return Result(iterations, elapsed / iterations, 1000 * iterations / elapsed ) 
}

fun report(name: String, results: Result) {
  var ops = results.iterations.toString() + " ops"
  var msPerOp = "%.2f".format(results.msPerOp) + " ms/op"
  var opsPerSecond = "%.2f".format(results.opsPerSecond) + " ops/sec"
  println( name + ": " + ops + ", " + msPerOp + ", " + opsPerSecond )
}

fun bench() {
	
	println("Begin Benchmark ...\n")
	
	// Benchmark signing.
	report("sign", benchmark( { 
		axlsign.sign(keys.privateKey, msg, null) 
	}));

	// Benchmark randomized signing.
	report("sign (randomized)", benchmark( { 
		axlsign.sign(keys.privateKey, msg, random) 
	}));

	// Benchmark verifying.
	report("verify", benchmark( { 
		axlsign.verify(keys.publicKey, msg, sig) 
	}));

	// Benchmark key generation.
	report("generateKeyPair", benchmark( { 
		axlsign.generateKeyPair(seed) 
	}));

	// Benchmark calculating shared key.
	report("sharedKey", benchmark( { 
		axlsign.sharedKey(keys.publicKey, keys.privateKey) 
	}));

	println("\nEnd Benchmark ...")
	
}
fun test() {
	
	println("Begin Test ...\n")
	
	var seed = axlsign.randomBytes(32)
	var rnd = axlsign.randomBytes(64)
	var keys = axlsign.generateKeyPair(seed)
	var msg = "lo esencial es invisible a los ojos !..."
	var amsg = msg.toIntArray()

	var sig = axlsign.sign(keys.privateKey, amsg, rnd);
	var res = axlsign.verify(keys.publicKey, amsg, sig);
	var res1 = axlsign.verify(keys.privateKey, amsg, sig);

	var sigmsg = axlsign.signMessage(keys.privateKey, amsg, null);
	var amsg2 = axlsign.openMessage(keys.publicKey, sigmsg)
	var msg2 = axlsign.openMessageStr(keys.publicKey, sigmsg)

	println("msg hex: " + amsg.toHex() )
	println("msg: " + amsg.debug())
	println("private key hex: " + keys.privateKey.toHex() )
	println("private key: " + keys.privateKey.debug() )
	println("public key hex: " + keys.publicKey.toHex() )
	println("public key: " + keys.publicKey.debug() )
	println("signature hex: " + sig.toHex() )
	println("signature: " + sig.debug() )
	println("res: $res")
	println("res1: $res1")
	println("sigmsg: " + sigmsg.debug() )
	println( msg )
	println( msg2 )
	
	println("\nEnd Test ...")
	
}
	
fun main(args: Array<String>) {	
	bench()
	test()	
}
