//
//  LKKCKeyPair.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-12.
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

#import "LKKCKeyPair.h"
#import "LKKCKey.h"

@implementation LKKCKeyPair 

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
