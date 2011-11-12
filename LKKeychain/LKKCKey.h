//
//  LKKCKey.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeychainItem.h"

typedef enum {
    LKKCKeyClassUnknown,
    LKKCKeyClassPublic,
    LKKCKeyClassPrivate,
    LKKCKeyClassSymmetric
} LKKCKeyClass;

@interface LKKCKey : LKKCKeychainItem

// The human-readable name of this password. Shows up as "Name" in Keychain Access. (kSecAttrLabel)
@property (nonatomic, retain) NSString *label; 

// The class of the key. (kSecAttrKeyClass)
@property (nonatomic, readonly) LKKCKeyClass keyClass; 

// The algorithm for which the key was generated. (kSecAttrKeyType)
@property (nonatomic, readonly) CSSM_ALGORITHMS keyType;

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
@property (nonatomic, readonly) int keySizeInBits; 
// Number of key bits that can be used in a cryptographic operation. (kSecAttrEffectiveKeySize)
@property (nonatomic, readonly) int effectiveKeySizeInBits; 

#if 0
// kSecAttrApplicationLabel
@property (nonatomic, retain) NSData *applicationLabel; 
// kSecAttrApplicationTag
@property (nonatomic, retain) NSData *applicationTag; 
#endif

@property (nonatomic, readonly) SecKeyRef SecKey;

@end

//kSecClassKey item attributes:
//kSecAttrAccess

