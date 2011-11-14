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

+ (LKKCKeyGenerator *)generator;

- (LKKCKeyPair *)generateRSAKeyPair;
- (LKKCKeyPair *)generateECDSAKeyPair;

- (LKKCKey *)generateAESKey;
- (LKKCKey *)generate3DESKey;

@property (nonatomic, assign) unsigned int keySize;

@property (nonatomic, retain) NSString *label; // kSecAttrLabel
@property (nonatomic, retain) NSData *keyID; // kSecAttrApplicationLabel
@property (nonatomic, retain) NSString *applicationLabel; // kSecAttrApplicationLabel
@property (nonatomic, retain) NSString *tag; // kSecAttrApplicationTag
@property (nonatomic, retain) LKKCKeychain *keychain;

@property (nonatomic, assign, getter = isExtractable) BOOL extractable; // defaults to YES

//@property (nonatomic, retain) LKKCAccess *access;
@end
