//
//  LKKCKey.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeychainItem.h"

typedef enum {
    LKKCKeyClassPublic,
    LKKCKeyClassPrivate,
    LKKCKeyClassSymmetric
} LKKCKeyClass;

@interface LKKCKey : LKKCKeychainItem

//kSecClassKey item attributes:
//kSecAttrAccess

#if 0
@property (nonatomic, readonly) LKKCKeyClass keyClass; // kSecAttrKeyClass
@property (nonatomic, retain) NSString *label; // kSecAttrLabel
@property (nonatomic, retain) NSData *applicationLabel; // kSecAttrApplicationLabel

@property (nonatomic, assign, getter = isPermanent) BOOL permanent; // kSecAttrIsPermanent
@property (nonatomic, retain) NSData *applicationTag; // kSecAttrApplicationTag
@property (nonatomic, assign) CSSM_ALGORITHMS keyType; // kSecAttrKeyType
@property (nonatomic, assign) id pseudoRandomFunction; // kSecAttrPRF
@property (nonatomic, retain) NSData *salt; // kSecAttrSalt
@property (nonatomic, assign) int numberOfRounds; // kSecAttrRounds
@property (nonatomic, assign) int keySizeInBits; // kSecAttrKeySizeInBits
@property (nonatomic, assign) int effectiveKeySizeInBits; // kSecAttrEffectiveKeySize

@property (nonatomic, assign) BOOL canEncrypt; // kSecAttrCanEncrypt
@property (nonatomic, assign) BOOL canDecrypt; // kSecAttrCanDecrypt
@property (nonatomic, assign) BOOL canDerive; // kSecAttrCanDerive
@property (nonatomic, assign) BOOL canSign; // kSecAttrCanSign
@property (nonatomic, assign) BOOL canVerify; // kSecAttrCanVerify
@property (nonatomic, assign) BOOL canWrap; // kSecAttrCanWrap
@property (nonatomic, assign) BOOL canUnwrap; // kSecAttrCanUnwrap
#endif

@end
