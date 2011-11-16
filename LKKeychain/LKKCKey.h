//
//  LKKCKey.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
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

@interface LKKCKey : LKKCKeychainItem

+ (LKKCKey *)keyWithSecKey:(SecKeyRef)skey;

+ (LKKCKey *)keyWithData:(NSData *)data 
                keyClass:(LKKCKeyClass)keyClass
                 keyType:(LKKCKeyType)keyType 
                 keySize:(UInt32)keySize;

// The human-readable name of this password. Shows up as "Name" in Keychain Access. (kSecAttrLabel)
@property (nonatomic, retain) NSString *label; 

// Key identifier. (kSecAttrApplicationLabel, a.k.a kSecKeyLabel)
// Both these properties map to the same keychain attribute; it is part of the primary key for key items.
// If you set one, the other is cleared. Use applicationLabel for symmetric keys and keyID for assymetric keys.
// Originally kSecKeyLabel was a binary attribute, and assymetric keys (especially those belonging to an identity) still rely on this: the system expects the value to be the SHA-1 hash of the public key.
// With the introduction of kSecAttrApplicationLabel, Apple decided to change the attribute's type to a UTF-8 string. This is fine for symmetric keys, but it makes it impossible to access or set raw data values (such as the hashes described above).
@property (nonatomic, retain) NSData *keyID; // Uses old API, for public and private keys
@property (nonatomic, retain) NSString *applicationLabel; // Uses new API, for symmetric keys

// Application-specific tag of your choice. (kSecAttrApplicationTag)
@property (nonatomic, retain) NSString *tag; 

// The class of the key (public, private or symmetric). (kSecAttrKeyClass)
@property (nonatomic, readonly) LKKCKeyClass keyClass; 

// The algorithm for which the key was generated (RSA, AES, etc). (kSecAttrKeyType)
@property (nonatomic, readonly) LKKCKeyType keyType;

// Whether this key is stored permanently in a keychain. (kSecAttrIsPermanent)
@property (nonatomic, readonly, getter = isPermanent) BOOL permanent; 

// Whether this key can be used to encrypt data. (kSecAttrCanEncrypt)
@property (nonatomic, readonly) BOOL canEncrypt; 
// Whether this key can be used to encrypt data. (kSecAttrCanDecrypt)
@property (nonatomic, readonly) BOOL canDecrypt;
// Whether this key can be used to derive another key. (kSecAttrCanDerive)
@property (nonatomic, readonly) BOOL canDerive;
// Whether this key can be used to create a digital signature. (kSecAttrCanSign)
@property (nonatomic, readonly) BOOL canSign; 
// Whether this key can be used to verify a digital signature. (kSecAttrCanVerify)
@property (nonatomic, readonly) BOOL canVerify;
// Whether this key can be used to wrap another key. (kSecAttrCanWrap)
@property (nonatomic, readonly) BOOL canWrap; 
// Whether this key can be used to unwrap another key. (kSecAttrCanUnwrap)
@property (nonatomic, readonly) BOOL canUnwrap; 

// The actual size of the key in the case of symmetric algorithms, 
// and the modulus size of the key in the case of asymmetric algorithms. (kSecAttrKeySizeInBits)
@property (nonatomic, readonly) int keySize; 
// Number of key bits that can be used in a cryptographic operation. (kSecAttrEffectiveKeySize)
@property (nonatomic, readonly) int effectiveKeySize;

// Returns the raw bits of the key, or nil if the key is not extractable.
- (NSData *)keyDataWithError:(NSError **)error;

@property (nonatomic, readonly) SecKeyRef SecKey;

- (NSData *)encryptData:(NSData *)plaintext error:(NSError **)error;
- (NSData *)decryptData:(NSData *)ciphertext error:(NSError **)error;

@end

//kSecClassKey item attributes:
//kSecAttrAccess

