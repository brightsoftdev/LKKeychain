//
//  LKKCKeyPair.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-12.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeyPair.h"
#import "LKKCKey.h"

@implementation LKKCKeyPair 
{
    LKKCKey *_publicKey;
    LKKCKey *_privateKey;
}

- (id)initWithPublicKey:(LKKCKey *)publicKey privateKey:(LKKCKey *)privateKey
{
    self = [super init];
    if (self == nil)
        return nil;
    _publicKey = [publicKey retain];
    _privateKey = [privateKey retain];
    return self;
}

- (void)dealloc
{
    [_publicKey release];
    [_privateKey release];
    [super dealloc];
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"<%@ %p> {\n    public: %@\n    private: %@\n}", 
            [self className], self, _publicKey, _privateKey];
}

- (LKKCKey *)publicKey
{
    return _publicKey;
}

- (LKKCKey *)privateKey
{
    return _privateKey;
}

- (NSData *)encryptData:(NSData *)plaintext error:(NSError **)error
{
    return [self.publicKey encryptData:plaintext error:error];
}

- (NSData *)decryptData:(NSData *)ciphertext error:(NSError **)error
{
    return [self.privateKey decryptData:ciphertext error:error];
}

@end
