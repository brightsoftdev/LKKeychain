//
//  LKKCKeyGenerator.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-13.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import <Foundation/Foundation.h>

@class LKKCKeychain;
@class LKKCKeyPair;
@class LKKCKey;

@interface LKKCKeyGenerator : NSObject
{
@private
    unsigned int _keySize;
    LKKCKeychain *_keychain;
    NSString *_label;
    NSData *_keyID;
    NSString *_applicationLabel;
    NSString *_tag;
    BOOL _extractable;
}

// Returns a generator that creates keys in the specified keychain.
// The keychain may be nil if you don't plan to store the generated keys permanently.
// If at all possible, please specify a keychain if you intend to store the key on one.
// Generating the key directly into a keychain is safer and more reliable than importing it later with -addToKeychain:.
+ (LKKCKeyGenerator *)generatorWithKeychain:(LKKCKeychain *)keychain;

- (LKKCKeyPair *)generateRSAKeyPair;
- (LKKCKeyPair *)generateECDSAKeyPair;

- (LKKCKey *)generateAESKey;
- (LKKCKey *)generate3DESKey;

// The size (in bits) of the generated key. Valid sizes depend on the algorithm.
// If you leave this at 0, the generated key will have a suitable default key size.
@property (nonatomic, assign) unsigned int keySize;

// The keychain into which to put the generated key. 
@property (nonatomic, retain) LKKCKeychain *keychain;

// Whether it will be possible to get the raw data of the generated keys. Defaults to YES.
@property (nonatomic, assign, getter = isExtractable) BOOL extractable;

// These properties correspond to those in LKKCKey.
@property (nonatomic, retain) NSString *label; // kSecAttrLabel
@property (nonatomic, retain) NSData *keyID; // kSecAttrApplicationLabel
@property (nonatomic, retain) NSString *applicationLabel; // kSecAttrApplicationLabel
@property (nonatomic, retain) NSString *tag; // kSecAttrApplicationTag

//@property (nonatomic, retain) LKKCAccess *access;
@end
