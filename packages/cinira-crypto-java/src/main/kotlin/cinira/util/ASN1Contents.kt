package cinira.util

import java.lang.IllegalStateException

class ASN1Contents private constructor(
    val numbers: List<Int>,
    val oids: List<ByteArray>,
    val strings: List<ByteArray>
) {
    companion object {
        fun fromBytes(bytes: ByteArray): ASN1Contents {
            val numbers = mutableListOf<Int>()
            val oids = mutableListOf<ByteArray>()
            val strings = mutableListOf<ByteArray>()
            parseASN1(bytes, numbers, oids, strings)
            return ASN1Contents(numbers.toList(), oids.toList(), strings.toList())
        }
    }
}

private fun parseASN1(
    buffer: ByteArray,
    numbers: MutableList<Int>,
    oids: MutableList<ByteArray>,
    strings: MutableList<ByteArray>
) {
    var pos = 0
    while (pos < buffer.size) {
        val tag = buffer[pos++].toInt()
        var length = buffer[pos++].toInt()
        if (0 != (length and 0x80)) {
            length = (0 until (length and 0x7f)).fold(0) { extLen, _ ->
                (extLen shl 8) or (buffer[pos++].toInt() and 0xff)
            }
        }
        val contents = buffer.sliceArray(pos until pos + length)
        pos += length
        if (0x30 == tag) {
            parseASN1(contents, numbers, oids, strings)
        } else if (0x03 == tag || 0x04 == tag) {
            strings += contents
        } else if (0x06 == tag) {
            oids += contents
        } else if (0x02 == tag) {
            var value = 0
            (0 until contents.size).forEach { i ->
                value = (value shl 8) or (contents[i].toInt() and 0xff)
            }
            numbers += value
        } else if (0x05 != tag) {
            throw IllegalStateException("Unexpected ASN.1 tag $tag.")
        }
    }
}
