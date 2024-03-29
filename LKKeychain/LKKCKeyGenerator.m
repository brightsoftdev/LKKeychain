//
//  LKKCKeyGenerator.m
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

#import "LKKCKeyGenerator.h"
#import "LKKCKeychain.h"
#import "LKKCKeyPair.h"
#import "LKKCKey.h"
#import "LKKCKey+Private.h"
#import "LKKCKeychainItem+Subclasses.h"
#import "LKKCUtil.h"

@interface LKKCKeyGenerator()
- (LKKCKeyPair *)_generateKeyPairWithKeyType:(LKKCKeyType)keyType keySize:(uint32)keySize error:(NSError **)error;
- (SecKeyRef)_copyKey:(SecKeyRef)skey keyType:(LKKCKeyType)keyType keySize:(int)keySize error:(NSError **)error;
- (LKKCKey *)_generateSymmetricKeyWithKeyType:(LKKCKeyType)keyType keySize:(uint32)keySize error:(NSError **)error;
@end

@implementation LKKCKeyGenerator
@synthesize keySize = _keySize;
@synthesize keychain = _keychain;
@synthesize label = _label;
@synthesize keyID = _keyID;
@synthesize applicationLabel = _applicationLabel;
@synthesize tag = _tag;
@synthesize extractable = _extractable;

+ (LKKCKeyGenerator *)generatorWithKeychain:(LKKCKeychain *)keychain
{
    LKKCKeyGenerator *generator = [[[LKKCKeyGenerator alloc] init] autorelease];
    generator.keychain = keychain;
    return generator;
}

- (id)init
{
    self = [super init];
    if (self == nil)
        return nil;
    _extractable = YES;
    return self;
}

- (void)dealloc
{
    [_keychain release];
    [_label release];
    [_keyID release];
    [_applicationLabel release];
    [_tag release];
    [super dealloc];
}

- (LKKCKeyPair *)_generateKeyPairWithKeyType:(LKKCKeyType)keyType keySize:(uint32)keySize error:(NSError **)error
{
    OSStatus status;
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    
    [parameters setObject:[LKKCKey _algorithmFromLKKCKeyType:keyType] forKey:kSecAttrKeyType];
    [parameters setObject:[NSNumber numberWithInt:keySize] forKey:kSecAttrKeySizeInBits];
    
    if (_label != nil)
        [parameters setObject:_label forKey:kSecAttrLabel];
    if (_tag != nil) {
        [parameters setObject:_tag forKey:kSecAttrApplicationTag];
    }
    
    if (_keychain != nil) {
        [parameters setObject:(id)_keychain.SecKeychain forKey:kSecUseKeychain];
        [parameters setObject:(id)kCFBooleanTrue forKey:kSecAttrIsPermanent];
    }
    else {
        // BUG: This doesn't work. SecKeyGeneratePair always puts the result on a keychain.
        [parameters setObject:(id)kCFBooleanFalse forKey:kSecAttrIsPermanent];
        LKKCReportError(errSecParam, error, @"Can't generate a key pair without a keychain");
        return nil;
    }
    
    SecAccessRef saccess = NULL;
    status = SecAccessCreate((CFStringRef)_label, NULL /* current app */, &saccess);
    if (status) {
        LKKCReportError(status, error, @"Can't create initial access object for generated key");
        return nil;
    }
    [parameters setObject:(id)saccess forKey:kSecAttrAccess];
    CFRelease(saccess);

    SecKeyRef spublicKey = NULL;
    SecKeyRef sprivateKey = NULL;
    status = SecKeyGeneratePair((CFDictionaryRef)parameters, &spublicKey, &sprivateKey);
    if (status) {
        LKKCReportError(status, error, @"Can't generate key pair");
        return nil;
    }
 
    LKKCKey *publicKey = [LKKCKey keyWithSecKey:spublicKey];
    CFRelease(spublicKey);

    LKKCKey *privateKey = [LKKCKey keyWithSecKey:sprivateKey];
    CFRelease(sprivateKey);

    LKKCKeyPair *keypair = [[[LKKCKeyPair alloc] initWithPublicKey:publicKey privateKey:privateKey] autorelease];
    return keypair;
}

- (LKKCKeyPair *)generateRSAKeyPairWithError:(NSError **)error
{
    unsigned int keySize = _keySize;
    if (keySize == 0)
        keySize = 2048;
    if ((keySize % 8) != 0 || keySize < kSecRSAMin || keySize > kSecRSAMax) {
        LKKCReportError(errSecParam, error, @"Invalid key size");
        return nil;
    }
    
    return [self _generateKeyPairWithKeyType:LKKCKeyTypeRSA keySize:keySize error:error];
}

- (LKKCKeyPair *)generateECDSAKeyPairWithError:(NSError **)error
{
    unsigned int keySize = _keySize;    
    if (keySize == 0)
        keySize = kSecp256r1;
    if (keySize != kSecp192r1 && keySize != kSecp256r1 && keySize != kSecp384r1 && keySize != kSecp521r1) {
        LKKCReportError(errSecParam, error, @"Invalid key size");
        return nil;
    }
    return [self _generateKeyPairWithKeyType:LKKCKeyTypeECDSA keySize:keySize error:error];
}

- (SecKeyRef)_copyKey:(SecKeyRef)skey keyType:(LKKCKeyType)keyType keySize:(int)keySize error:(NSError **)error
{
    SecKeyRef skeyCopy = NULL;
    @autoreleasepool {
        LKKCKey *tempKey = [LKKCKey keyWithSecKey:skey];
        NSData *data = [tempKey keyDataWithError:NULL];
        if (data == nil)
            return NULL;

        NSMutableDictionary *attributes = [NSMutableDictionary dictionary];
        [attributes setObject:kSecClassKey forKey:kSecClass];
        [attributes setObject:kSecAttrKeyClassSymmetric forKey:kSecAttrKeyClass];
        [attributes setObject:[LKKCKey _algorithmFromLKKCKeyType:keyType] forKey:kSecAttrKeyType];
        [attributes setObject:[NSNumber numberWithInt:keySize] forKey:kSecAttrKeySizeInBits];
        [attributes setObject:(id)kCFBooleanTrue forKey:kSecAttrCanEncrypt];
        [attributes setObject:(id)kCFBooleanTrue forKey:kSecAttrCanDecrypt];
        [attributes setObject:(id)kCFBooleanTrue forKey:kSecAttrCanDerive];
        [attributes setObject:(id)kCFBooleanTrue forKey:kSecAttrCanWrap];
        [attributes setObject:(id)kCFBooleanTrue forKey:kSecAttrCanUnwrap];
        [attributes setObject:(id)kCFBooleanTrue forKey:kSecAttrCanSign];
        [attributes setObject:(id)kCFBooleanTrue forKey:kSecAttrCanVerify];
        
        CFErrorRef cferror = NULL;
        skeyCopy = SecKeyCreateFromData((CFDictionaryRef)attributes, (CFDataRef)data, &cferror);
        if (skey == NULL) {
            LKKCReportError((OSStatus)CFErrorGetCode(cferror), error, @"Can't create key copy");
            CFRelease(cferror);
            return NULL;
        }
    }
    [(id)skeyCopy autorelease];
    return skeyCopy;
}

- (LKKCKey *)_generateSymmetricKeyWithKeyType:(LKKCKeyType)keyType keySize:(uint32)keySize error:(NSError **)error
{
    if (_extractable || _keychain == nil) {
        // SecKeyGenerateSymmetric can only create non-extractable keys.
        // When the user requested an extractable key or when we create a floating key,
        // use the older SecKeyGenerate instead.
        SecKeychainRef skeychain = NULL;
        if (_keychain != nil)
            skeychain = _keychain.SecKeychain;
        
        CSSM_ALGORITHMS algid = [LKKCKey _cssmAlgorithmFromLKKCKeyType:keyType];
        
        CSSM_KEYUSE keyUse = CSSM_KEYUSE_ANY | CSSM_KEYUSE_ENCRYPT | CSSM_KEYUSE_DECRYPT | CSSM_KEYUSE_WRAP | CSSM_KEYUSE_UNWRAP | CSSM_KEYUSE_SIGN | CSSM_KEYUSE_VERIFY;
        
        CSSM_KEYATTR_FLAGS keyAttr = CSSM_KEYATTR_RETURN_DEFAULT | CSSM_KEYATTR_EXTRACTABLE;
        
        SecAccessRef saccess = NULL;
        OSStatus status = SecAccessCreate((CFStringRef)_label, NULL /* current app */, &saccess);
        if (status) {
            LKKCReportError(status, error, @"Can't create access object for newly generated key");
            return nil;
        }
        SecKeyRef skey = NULL;
        status = SecKeyGenerate(skeychain, algid, keySize, 0, keyUse, keyAttr, saccess, &skey);
        CFRelease(saccess);
        if (status) {
            LKKCReportError(status, error, @"Can't generate symmetric key");
            return nil;
        }
        
        if (skeychain == NULL) {
            // SecItemAdd doesn't like floating keys generated by SecKeyGenerate/SecKeyGenerateSymmetric:
            // It fails with errSecInvalidKeyRef.
            // However, it gladly accepts a duplicate key created by SecKeyCreateFromData.
            SecKeyRef skeyCopy = [self _copyKey:skey keyType:keyType keySize:keySize error:error];
            if (skeyCopy) {
                CFRelease(skey);
                skey = (SecKeyRef)CFRetain(skeyCopy);
            }
        }

        LKKCKey *key = [LKKCKeychainItem itemWithClass:kSecClassKey
                                       SecKeychainItem:(SecKeychainItemRef)skey 
                                            attributes:nil];
        CFRelease(skey);
        
        if (_label != nil)
            key.label = _label;
        if (_applicationLabel != nil)
            key.applicationLabel = _applicationLabel;
        if (_keyID != nil)
            key.keyID = _keyID;
        if (_tag != nil)
            key.tag = _tag;
        if (_keychain != nil && ![key saveItemWithError:NULL]) {
            [key deleteItemWithError:NULL];
            return nil;
        }
        
        return key;    
    }
    else {
        NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    
        [parameters setObject:[NSNumber numberWithInt:keySize] forKey:kSecAttrKeySizeInBits];
        [parameters setObject:[LKKCKey _algorithmFromLKKCKeyType:keyType] forKey:kSecAttrKeyType];
        
        if (_label != nil)
            [parameters setObject:_label forKey:kSecAttrLabel];
#if 0 
        // rdar://10618031 SecKeyGenerateSymmetric expects string values for kSecAttrApplicationTag.
        // Work around by setting the tag in a separate step after generating the key.
        if (_tag != nil)
            [parameters setObject:_tag forKey:kSecAttrApplicationTag];
#endif
        
        if (_keychain != nil) {
            [parameters setObject:(id)_keychain.SecKeychain forKey:kSecUseKeychain];
            [parameters setObject:(id)kCFBooleanTrue forKey:kSecAttrIsPermanent];
        }
        else {
            [parameters setObject:(id)kCFBooleanFalse forKey:kSecAttrIsPermanent];
        }
        
        SecAccessRef saccess = NULL;
        OSStatus status = SecAccessCreate((CFStringRef)_label, NULL /* current app */, &saccess);
        if (status) {
            LKKCReportError(status, error, @"Can't create access object for newly generated key");
            return nil;
        }
        [parameters setObject:(id)saccess forKey:kSecAttrAccess];
        CFRelease(saccess);

        CFErrorRef cferror = NULL;
        SecKeyRef skey = SecKeyGenerateSymmetric((CFDictionaryRef)parameters, &cferror);
        if (skey == NULL) {
            LKKCReportError((OSStatus)CFErrorGetCode(cferror), NULL, @"Can't generate symmetric key");
            CFRelease(cferror);
            return nil;
        }
        
        if (_keychain == nil) {
            // SecItemAdd doesn't like floating keys generated by SecKeyGenerate/SecKeyGenerateSymmetric:
            // It fails with errSecInvalidKeyRef.
            // However, it gladly accepts a duplicate key created by SecKeyCreateFromData.
            SecKeyRef skeyCopy = [self _copyKey:skey keyType:keyType keySize:keySize error:error];
            if (skeyCopy) {
                CFRelease(skey);
                skey = (SecKeyRef)CFRetain(skeyCopy);
            }
        }

        LKKCKey *key = [LKKCKeychainItem itemWithClass:kSecClassKey
                                       SecKeychainItem:(SecKeychainItemRef)skey 
                                            attributes:nil];
        CFRelease(skey);

        if (_tag != nil && _keychain != nil) {
            // rdar://10618031 SecKeyGenerateSymmetric expects string values for kSecAttrApplicationTag.
            // Work around by setting the tag in a separate step after generating the key.
            key.tag = _tag;
            if (![key saveItemWithError:error]) {
                [key deleteItemWithError:NULL];
                return nil;
            }
        }
        
        if (_keychain == nil) {
            // The label/tag attributes aren't saved to a keychain yet; store them in the 
            // LKKCKey instance until the user calls -[LKKCKey addItemToKeychain:error:].
            if (_label != nil)
                key.label = _label;
            if (_keyID != nil)
                key.keyID = _keyID;
            if (_tag != nil)
                key.tag = _tag;
        }
        return key;    
    }
}

- (LKKCKey *)generateAESKeyWithError:(NSError **)error
{
    unsigned int keySize = _keySize;    
    if (keySize == 0)
        keySize = kSecAES128;
    if (keySize != kSecAES128 && keySize != kSecAES192 && keySize != kSecAES256) {
        LKKCReportError(errSecParam, NULL, @"Invalid key size");
        return nil;
    }
    return [self _generateSymmetricKeyWithKeyType:LKKCKeyTypeAES keySize:keySize error:error];
}

- (LKKCKey *)generate3DESKeyWithError:(NSError **)error
{
    unsigned int keySize = _keySize;    
    if (keySize == 0)
        keySize = kSec3DES192;
    if (keySize != kSec3DES192) {
        LKKCReportError(errSecParam, NULL, @"Invalid key size");
        return nil;
    }
    return [self _generateSymmetricKeyWithKeyType:LKKCKeyType3DES keySize:keySize error:error];
}

@end
