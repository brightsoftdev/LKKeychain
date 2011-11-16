//
//  LKKCCryptoContext.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-15.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

@class LKKCKey;
@interface LKKCCryptoContext : NSObject
{
@private
    LKKCKey *_key;
    CSSM_CC_HANDLE _cchandle;
}

+ (LKKCCryptoContext *)cryptoContextForKey:(LKKCKey *)key operation:(CSSM_ACL_AUTHORIZATION_TAG)operation error:(NSError **)error;

- (NSData *)encryptData:(NSData *)plaintext error:(NSError **)error;
- (NSData *)decryptData:(NSData *)ciphertext error:(NSError **)error;

@end
