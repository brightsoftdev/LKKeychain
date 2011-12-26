//
//  LKKCKeyGenerator.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-13.
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

#import <Foundation/Foundation.h>

@class LKKCKeychain;
@class LKKCKeyPair;
@class LKKCKey;

/** A key generator that can generate symmetric and asymmetric keys for various cryptographic algorithms. */
@interface LKKCKeyGenerator : NSObject
{
@private
    unsigned int _keySize;
    LKKCKeychain *_keychain;
    NSString *_label;
    NSData *_keyID;
    NSString *_applicationLabel;
    NSData *_tag;
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

/** The size (in bits) of the generated key. Valid sizes depend on the algorithm.

 If you leave this at 0, the generated key will have a suitable default key size. */
@property (nonatomic, assign) unsigned int keySize;

/// The keychain into which to put the generated key. 
@property (nonatomic, retain) LKKCKeychain *keychain;

/// Whether it will be possible to get the raw data of the generated keys. Defaults to YES.
@property (nonatomic, assign, getter = isExtractable) BOOL extractable;

// These properties correspond to those in LKKCKey.
@property (nonatomic, retain) NSString *label; // kSecAttrLabel
@property (nonatomic, retain) NSData *keyID; // kSecAttrApplicationLabel
@property (nonatomic, retain) NSString *applicationLabel; // kSecAttrApplicationLabel
@property (nonatomic, retain) NSData *tag; // kSecAttrApplicationTag

//@property (nonatomic, retain) LKKCAccess *access;
@end
