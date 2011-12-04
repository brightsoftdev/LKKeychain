//
//  LKKCKey.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright © 2011, Károly Lőrentey. All rights reserved.
//  
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are met:
//  
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//  * Neither the name of Károly Lőrentey nor the names of its contributors 
//    may be used to endorse or promote products derived from this software 
//    without specific prior written permission.
//  
//  **This software is provided by the copyright holders and contributors "as is" and
//  any express or implied warranties, including, but not limited to, the implied
//  warranties of merchantability and fitness for a particular purpose are
//  disclaimed. In no event shall Károly Lőrentey be liable for any
//  direct, indirect, incidental, special, exemplary, or consequential damages
//  (including, but not limited to, procurement of substitute goods or services;
//  loss of use, data, or profits; or business interruption) however caused and
//  on any theory of liability, whether in contract, strict liability, or tort
//  (including negligence or otherwise) arising in any way out of the use of this
//  software, even if advised of the possibility of such damage.**
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
 */
@property (nonatomic, retain) NSData *keyID;

/** Key identifier for symmetric keys. (kSecAttrApplicationLabel, a.k.a kSecKeyLabel)

 Both <keyID> and <applicationLabel>  map to the same keychain attribute; it is part of the primary key for key items.
 If you set one, the other is cleared. Use <applicationLabel> for symmetric keys and <keyID> for asymetric keys.
 
 Originally kSecKeyLabel was a binary attribute, and asymetric keys (especially those belonging to an identity) still rely on this: the system expects the value to be the SHA-1 hash of the public key.
 
 With the introduction of kSecAttrApplicationLabel, Apple decided to change the attribute's type to a UTF-8 string. This is fine for symmetric keys, but it makes it impossible to access or set raw data values (such as the hashes described above).
 */
@property (nonatomic, retain) NSString *applicationLabel;

/** --------------------------------------------------------------------------------
 @name Key attributes
 -------------------------------------------------------------------------------- */

/// Application-specific tag of your choice. (kSecAttrApplicationTag)
@property (nonatomic, retain) NSString *tag; 

/// The class of the key (public, private or symmetric). (kSecAttrKeyClass)
@property (nonatomic, readonly) LKKCKeyClass keyClass; 

/// The algorithm for which the key was generated (RSA, AES, etc). (kSecAttrKeyType)
@property (nonatomic, readonly) LKKCKeyType keyType;

/// Whether this key is stored permanently in a keychain. (kSecAttrIsPermanent)
@property (nonatomic, readonly, getter = isPermanent) BOOL permanent; 

/// Whether this key can be used to encrypt data. (kSecAttrCanEncrypt)
@property (nonatomic, readonly) BOOL canEncrypt; 
/// Whether this key can be used to encrypt data. (kSecAttrCanDecrypt)
@property (nonatomic, readonly) BOOL canDecrypt;
/// Whether this key can be used to derive another key. (kSecAttrCanDerive)
@property (nonatomic, readonly) BOOL canDerive;
/// Whether this key can be used to create a digital signature. (kSecAttrCanSign)
@property (nonatomic, readonly) BOOL canSign; 
/// Whether this key can be used to verify a digital signature. (kSecAttrCanVerify)
@property (nonatomic, readonly) BOOL canVerify;
/// Whether this key can be used to wrap another key. (kSecAttrCanWrap)
@property (nonatomic, readonly) BOOL canWrap; 
/// Whether this key can be used to unwrap another key. (kSecAttrCanUnwrap)
@property (nonatomic, readonly) BOOL canUnwrap; 

/* The actual size of the key in the case of symmetric algorithms, 
 and the modulus size of the key in the case of asymmetric algorithms. (kSecAttrKeySizeInBits)
 */
@property (nonatomic, readonly) int keySize; 
/// Number of key bits that can be used in a cryptographic operation. (kSecAttrEffectiveKeySize)
@property (nonatomic, readonly) int effectiveKeySize;

/** Returns the raw bits of the key.
 @param error On output, the error that occurred in case the data could not be extraced (optional).
 @return The raw bits of the key, of nil if the key data is not extractable from the keychain.
 */
- (NSData *)keyDataWithError:(NSError **)error;


/// The underlying `SecKey` reference.
@property (nonatomic, readonly) SecKeyRef SecKey;

- (NSData *)encryptData:(NSData *)plaintext error:(NSError **)error;
- (NSData *)decryptData:(NSData *)ciphertext error:(NSError **)error;

@end

//kSecClassKey item attributes:
//kSecAttrAccess

