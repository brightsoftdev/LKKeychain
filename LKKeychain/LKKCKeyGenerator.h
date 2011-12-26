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

/** --------------------------------------------------------------------------------
 @name Factory Method
 -------------------------------------------------------------------------------- */

/** Return a generator that creates keys in the specified keychain.
 
 The keychain may be nil if you don't plan to store the generated keys permanently.
 If at all possible, please specify a keychain if you intend to store the key on one.
 Generating the key directly into a keychain is safer and more reliable than importing it later
 with <[LKKCKeychainItem addToKeychain:error:]>.
 
 @param keychain The keychain into which keys will be generated.
 @return A new key generator instance.
 */
+ (LKKCKeyGenerator *)generatorWithKeychain:(LKKCKeychain *)keychain;

/** --------------------------------------------------------------------------------
 @name Key Generation
 -------------------------------------------------------------------------------- */

/** Generate a new RSA key pair.
 @param error On output, the error that occurred in case the key could not be generated (optional).
 @return A new RSA key pair, or nil if there was an error.
 */
- (LKKCKeyPair *)generateRSAKeyPairWithError:(NSError **)error;

/** Generate a new ECDSA key pair.
 @param error On output, the error that occurred in case the key could not be generated (optional).
 @return A new ECDSA key pair, or nil if there was an error.
 */
- (LKKCKeyPair *)generateECDSAKeyPairWithError:(NSError **)error;

/** Generate a new AES key. 
 @param error On output, the error that occurred in case the key could not be generated (optional).
 @return A new AES key, or nil if there was an error.
 */
- (LKKCKey *)generateAESKeyWithError:(NSError **)error;

/** Generate a new 3DES key. 
 @param error On output, the error that occurred in case the key could not be generated (optional).
 @return A new 3DES key, or nil if there was an error.
 */
- (LKKCKey *)generate3DESKeyWithError:(NSError **)error;

/** --------------------------------------------------------------------------------
 @name Key Parameters
 -------------------------------------------------------------------------------- */

/** The size (in bits) of the generated key. Valid sizes depend on the algorithm.

 If you leave this at 0, the generated key will have a suitable default key size. 
 */
@property (nonatomic, assign) unsigned int keySize;

/** The keychain into which to put the generated key. 
 */
@property (nonatomic, retain) LKKCKeychain *keychain;

/** Whether it will be possible to get the raw data of the generated keys. Defaults to YES.
 */
@property (nonatomic, assign, getter = isExtractable) BOOL extractable;

/** The initial value for the `label` property of the generated key.
 @see [LKKCKey label]
 */
@property (nonatomic, retain) NSString *label;

/** The initial value for the `keyID` property of the generated key.
 @see [LKKCKey keyID]
 */
@property (nonatomic, retain) NSData *keyID;

/** The initial value for the `applicationLabel` property of the generated key.
 @see [LKKCKey applicationLabel]
 */
@property (nonatomic, retain) NSString *applicationLabel;
 
/** The initial value for the `tag` property of the generated key.
 @see [LKKCKey tag]
 */
@property (nonatomic, retain) NSData *tag;

//@property (nonatomic, retain) LKKCAccess *access;
@end
