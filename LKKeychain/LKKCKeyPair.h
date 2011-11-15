//
//  LKKCKeyPair.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-12.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import <Foundation/Foundation.h>

@class LKKCKey;
@interface LKKCKeyPair : NSObject
- (id)initWithPublicKey:(LKKCKey *)publicKey privateKey:(LKKCKey *)privateKey;
@property (nonatomic, readonly) LKKCKey *publicKey;
@property (nonatomic, readonly) LKKCKey *privateKey;

- (NSData *)encryptData:(NSData *)plaintext error:(NSError **)error;
- (NSData *)decryptData:(NSData *)ciphertext error:(NSError **)error;

@end
