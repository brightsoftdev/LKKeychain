//
//  LKKCKeyPair.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-12.
//  Copyright © 2011, Károly Lőrentey. All rights reserved.
//  
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions
//  are met:
//  
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above
//    copyright notice, this list of conditions and the following
//    disclaimer in the documentation and/or other materials provided
//    with the distribution.
//  * Neither the name of Károly Lőrentey nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//  
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
//  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL KÁROLY LŐRENTEY BE LIABLE FOR ANY
//  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
//  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
    return [self.publicKey encryptData:plaintext initVector:nil error:error];
}

- (NSData *)decryptData:(NSData *)ciphertext error:(NSError **)error
{
    return [self.privateKey decryptData:ciphertext initVector:nil error:error];
}

@end
