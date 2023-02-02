/*
* KMAC
* (C) 2023 Falko Strenzke
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

namespace Botan {

/**
* KMAC
*/
// https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-185.pdf
// Basic approach: all "encode" and "pad" functions can be implemented plain as they are used only for the customization string S.
/*
right_encode(x):
left_encode(x):
bytepad(X, w)
*/

/*
encode_string(S):
Validity Conditions: 0 ≤ len(S) < 22040
1. Return left_encode(len(S)) || S.
*/

    /*
cSHAKE256(X, L, N, S):
Validity Conditions: len(N)< 22040 and len(S)< 22040
1. If N = "" and S = "":
return SHAKE256(X, L);
2. Else:
return KECCAK[512](bytepad(encode_string(N) || encode_string(S), 136) || X || 00, L)
*/ 

/*
KMAC256(K, X, L, S):
Validity Conditions: len(K) <22040 and 0 ≤ L < 22040 and len(S) < 22040
1. newX = bytepad(encode_string(K), 136) || X || right_encode(L).
2. return cSHAKE256(newX, L, “KMAC”, S)
*/

/* - O Implement cShake256 as new hash function
 * - O Implement KMAC256
 *
 * */

}
