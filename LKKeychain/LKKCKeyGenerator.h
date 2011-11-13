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

@property (nonatomic, retain) NSString *label;
@property (nonatomic, retain) NSString *tag;
@property (nonatomic, retain) LKKCKeychain *keychain;

//@property (nonatomic, retain) LKKCAccess *access;
@end