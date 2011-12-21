//
//  LKKCKey.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright © 2011, Károly Lőrentey. All rights reserved.
//  
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions
//  are met:
//  
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above
//    copyright notice, this list of conditions and the following
//    disclaimer in the documentation and/or other materials provided
//    with the distribution.
//  * Neither the name of Károly Lőrentey nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//  
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
//  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL KÁROLY LŐRENTEY BE LIABLE FOR ANY
//  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
//  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 

#import <LKKeychain/LKKCKeychainItem.h>

typedef enum {
    LKKCKeyClassUnknown,
    LKKCKeyClassPublic,
    LKKCKeyClassPrivate,
    LKKCKeyClassSymmetric
} LKKCKeyClass;

typedef enum {
    LKKCKeyTypeUnknown,
    LKKCKeyTypeRSA,
    LKKCKeyTypeDSA,
    LKKCKeyTypeAES,
    LKKCKeyTypeDES,
    LKKCKeyType3DES,
    LKKCKeyTypeRC4,
    LKKCKeyTypeRC2,
    LKKCKeyTypeCAST,
    LKKCKeyTypeECDSA
} LKKCKeyType;

/** Represents a cryptographic key. */
@interface LKKCKey : LKKCKeychainItem

+ (LKKCKey *)keyWithSecKey:(SecKeyRef)skey;

+ (LKKCKey *)keyWithData:(NSData *)data 
                keyClass:(LKKCKeyClass)keyClass
                 keyType:(LKKCKeyType)keyType 
                 keySize:(UInt32)keySize;

// The human-readable name of this password. Shows up as "Name" in Keychain Access. (kSecAttrLabel)
@property (nonatomic, retain) NSString *label; 

/** --------------------------------------------------------------------------------
 @name Key identifiers
 -------------------------------------------------------------------------------- */

/** Key identifier for public and private keys. (kSecAttrApplicationLabel, a.k.a kSecKeyLabel)
 
 Both <keyID> and <applicationLabel>  map to the same keychain attribute; it is part of the primary key for key items.
 If you set one, the other is cleared. Use <applicationLabel> for symmetric keys and <keyID> for asymetric keys.
 
 Originally kSecKeyLabel was a binary attribute, and asymetric keys (especially those belonging to an identity) still rely on this: the system expects the value to be the SHA-1 hash of the public key.
 
 With the introduction of kSecAttrApplicationLabel, Apple decided to change the attribute's type to a UTF-8 string. This is fine for symmetric keys, but it makes it impossible to access or set raw data values (such as the hashes described above).
 
 This property is part of the primary key for Key items.
 */
@property (nonatomic, retain) NSData *keyID;

/** Key identifier for symmetric keys. (kSecAttrApplicationLabel, a.k.a kSecKeyLabel)

 Both <keyID> and <applicationLabel>  map to the same keychain attribute; it is part of the primary key for key items.
 If you set one, the other is cleared. Use <applicationLabel> for symmetric keys and <keyID> for asymetric keys.
 
 Originally kSecKeyLabel was a binary attribute, and asymetric keys (especially those belonging to an identity) still rely on this: the system expects the value to be the SHA-1 hash of the public key.
 
 With the introduction of kSecAttrApplicationLabel, Apple decided to change the attribute's type to a UTF-8 string. This is fine for symmetric keys, but it makes it impossible to access or set raw data values (such as the hashes described above).
 
 This property is part of the primary key for Key items.
 */
@property (nonatomic, retain) NSString *applicationLabel;

/** --------------------------------------------------------------------------------
 @name Key attributes
 -------------------------------------------------------------------------------- */

/** Application-specific tag of your choice.
 
 This property corresponds to the `kSecAttrApplicationTag` attribute.
 
 This property is part of the primary key for Key items.
 */
@property (nonatomic, retain) NSString *tag; 

/** The class of the key (public, private or symmetric).
 
 This property corresponds to the `kSecAttrKeyClass` attribute.
 */
@property (nonatomic, readonly) LKKCKeyClass keyClass; 

/** The algorithm for which the key was generated (RSA, AES, etc).
 
 This property corresponds to the `kSecAttrKeyType` attribute.
 
 This property is part of the primary key for Key items.
 */
@property (nonatomic, readonly) LKKCKeyType keyType;

/** Whether this key is stored permanently in a keychain. 
 
 This property corresponds to the `kSecAttrIsPermanent` attribute.
 */
@property (nonatomic, readonly, getter = isPermanent) BOOL permanent; 

/** Whether this key can be used to encrypt data.
 
 This property corresponds to the `kSecAttrCanEncrypt` attribute.
 */
@property (nonatomic, readonly) BOOL canEncrypt; 

/** Whether this key can be used to encrypt data.
 
 This property corresponds to the `kSecAttrCanDecrypt` attribute.
 */
@property (nonatomic, readonly) BOOL canDecrypt;

/** Whether this key can be used to derive another key.
 
 This property corresponds to the `kSecAttrCanDerive` attribute.
 */
@property (nonatomic, readonly) BOOL canDerive;

/** Whether this key can be used to create a digital signature.
 
 This property corresponds to the `kSecAttrCanSign` attribute.
 */
@property (nonatomic, readonly) BOOL canSign; 

/** Whether this key can be used to verify a digital signature.
 
 This property corresponds to the `kSecAttrCanVerify` attribute.
 */
@property (nonatomic, readonly) BOOL canVerify;

/** Whether this key can be used to wrap another key.
 
 This property corresponds to the `kSecAttrCanWrap` attribute.
 */
@property (nonatomic, readonly) BOOL canWrap; 

/** Whether this key can be used to unwrap another key.
 
 This property corresponds to the `kSecAttrCanUnwrap` attribute.
 */
@property (nonatomic, readonly) BOOL canUnwrap; 

/** The actual size of the key in the case of symmetric algorithms, 
 and the modulus size of the key in the case of asymmetric algorithms.
 
 This property corresponds to the `kSecAttrKeySizeInBits` attribute.
 
 This property is part of the primary key for Key items.
 */
@property (nonatomic, readonly) int keySize; 

/** Number of key bits that can be used in a cryptographic operation.
 
 This property corresponds to the `kSecAttrEffectiveKeySize` attribute.
 
 This property is part of the primary key for Key items.
 */
@property (nonatomic, readonly) int effectiveKeySize;

/** --------------------------------------------------------------------------------
 @name Accessing The Raw Key Data
 -------------------------------------------------------------------------------- */

/** Returns the raw bits of the key.
 @param error On output, the error that occurred in case the data could not be extraced (optional).
 @return The raw bits of the key, of nil if the key data is not extractable from the keychain.
 */
- (NSData *)keyDataWithError:(NSError **)error;

/** --------------------------------------------------------------------------------
 @name Low-Level Access
 -------------------------------------------------------------------------------- */

/** The underlying `SecKey` reference.
 */
@property (nonatomic, readonly) SecKeyRef SecKey;

/** --------------------------------------------------------------------------------
 @name Encryption and Decryption
 -------------------------------------------------------------------------------- */

/** Return the block size for this key. */
- (UInt32)blockSize;

/** Return a pseudorandom piece of data that is a suitable initialization vector for this key.
 Returns nil for assymetric keys.
 */
- (NSData *)randomInitVector;

/** Encrypt a piece of data with this key. 
 
 To decrypt data encrypted by a symmetric key, you'll need a copy of the same key 
 and the same initialization vector. You don't need to keep the IV private; it is usually transmitted
 in the same channel as the encrypted data (for example, by prepending the IV to the ciphertext).
 
 To decrypt data encrypted by an asymmetric key, you'll need a copy of the other key in the keypair.
 
 @param plaintext The data to encrypt.
 @param initVector The initialization vector to use. Required for symmetric keys.
 @param error On output, the error that occured in case the data could not be encrypted (optional).
 @return The encrypted data.
 @see randomInitVector
 */
- (NSData *)encryptData:(NSData *)plaintext initVector:(NSData *)iv error:(NSError **)error;

/** Decrypt a piece of ciphertext with this key.

 @param ciphertext The encrypted data.
 @param initVector The initialization vector that was used to encrypt.
 @param error
 @return The decrypted data.
 */
- (NSData *)decryptData:(NSData *)ciphertext initVector:(NSData *)iv error:(NSError **)error;

@end

//kSecClassKey item attributes:
//kSecAttrAccess

