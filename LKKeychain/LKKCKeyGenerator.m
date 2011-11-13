//
//  LKKCKeyGenerator.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-13.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeyGenerator.h"
#import "LKKCKeychain.h"
#import "LKKCKeyPair.h"
#import "LKKCKey.h"
#import "LKKCUtil.h"

@interface LKKCKeyGenerator()
- (LKKCKeyPair *)_generateKeyPairWithAlgorithm:(CFTypeRef)algorithm keySize:(uint32)keySize;
- (LKKCKey *)_generateSymmetricKeyWithAlgorithm:(CFTypeRef)algorithm keySize:(uint32)keySize;
@end

@implementation LKKCKeyGenerator
{
    unsigned int _keySize;
    LKKCKeychain *_keychain;
    NSString *_label;
    NSString *_tag;
}
@synthesize keySize = _keySize;
@synthesize keychain = _keychain;
@synthesize label = _label;
@synthesize tag = _tag;

+ (LKKCKeyGenerator *)generator
{
    return [[[LKKCKeyGenerator alloc] init] autorelease];
}

- (LKKCKeyPair *)_generateKeyPairWithAlgorithm:(CFTypeRef)algorithm keySize:(uint32)keySize
{
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    
    [parameters setObject:kSecAttrKeyTypeRSA forKey:kSecAttrKeyType];
    [parameters setObject:[NSNumber numberWithInt:keySize] forKey:kSecAttrKeySizeInBits];
    
    if (_label != nil)
        [parameters setObject:_label forKey:kSecAttrLabel];
    if (_tag != nil)
        [parameters setObject:_tag forKey:kSecAttrApplicationTag];
    
    if (_keychain != nil) {
        [parameters setObject:(id)_keychain.SecKeychain forKey:kSecUseKeychain];
        [parameters setObject:(id)kCFBooleanTrue forKey:kSecAttrIsPermanent];
    }
    else {
        [parameters setObject:(id)kCFBooleanFalse forKey:kSecAttrIsPermanent];
    }
    
    SecKeyRef spublicKey = NULL;
    SecKeyRef sprivateKey = NULL;
    OSStatus status = SecKeyGeneratePair((CFDictionaryRef)parameters, &spublicKey, &sprivateKey);
    if (status) {
        LKKCReportError(status, NULL, @"Can't generate key pair");
        return nil;
    }
 
    LKKCKey *publicKey = [LKKCKey keyWithSecKey:spublicKey];
    CFRelease(spublicKey);

    LKKCKey *privateKey = [LKKCKey keyWithSecKey:sprivateKey];
    CFRelease(sprivateKey);

    LKKCKeyPair *keypair = [[[LKKCKeyPair alloc] initWithPublicKey:publicKey privateKey:privateKey] autorelease];
    return keypair;
}

- (LKKCKeyPair *)generateRSAKeyPair
{
    unsigned int keySize = _keySize;
    if (keySize == 0)
        keySize = 2048;
    if ((keySize % 8) != 0 || keySize < kSecRSAMin || keySize > kSecRSAMax) {
        LKKCReportError(errSecParam, NULL, @"Invalid key size");
        return nil;
    }
    
    return [self _generateKeyPairWithAlgorithm:kSecAttrKeyTypeRSA keySize:keySize];
}

- (LKKCKeyPair *)generateECDSAKeyPair
{
    unsigned int keySize = _keySize;    
    if (keySize == 0)
        keySize = kSecp256r1;
    if (keySize != kSecp192r1 && keySize != kSecp256r1 && keySize != kSecp384r1 && keySize != kSecp521r1) {
        LKKCReportError(errSecParam, NULL, @"Invalid key size");
        return nil;
    }
    return [self _generateKeyPairWithAlgorithm:kSecAttrKeyTypeECDSA keySize:keySize];
}

- (LKKCKey *)_generateSymmetricKeyWithAlgorithm:(CFTypeRef)algorithm keySize:(uint32)keySize
{
#if 0
    SecKeyRef skey = NULL;
    CSSM_ALGORITHMS algid = (CSSM_ALGORITHMS)[(id)algorithm integerValue];
    CSSM_KEYUSE keyUse = CSSM_KEYUSE_ENCRYPT | CSSM_KEYUSE_DECRYPT | CSSM_KEYUSE_WRAP | CSSM_KEYUSE_UNWRAP | CSSM_KEYUSE_SIGN | CSSM_KEYUSE_VERIFY;
    CSSM_KEYATTR_FLAGS keyAttr = CSSM_KEYATTR_EXTRACTABLE | CSSM_KEYATTR_RETURN_DEFAULT;
    OSStatus status = SecKeyGenerate(NULL, algid, keySize, 0, keyUse, keyAttr, NULL, &skey);
    if (status) {
        LKKCReportError(status, NULL, @"Can't generate symmetric key");
        return nil;
    }
#else
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    
    [parameters setObject:[NSNumber numberWithInt:keySize] forKey:kSecAttrKeySizeInBits];
    [parameters setObject:algorithm forKey:kSecAttrKeyType];
    
    if (_label != nil)
        [parameters setObject:_label forKey:kSecAttrLabel];
    if (_tag != nil)
        [parameters setObject:_tag forKey:kSecAttrApplicationTag];
    
    if (_keychain != nil) {
        [parameters setObject:(id)_keychain.SecKeychain forKey:kSecUseKeychain];
        [parameters setObject:(id)kCFBooleanTrue forKey:kSecAttrIsPermanent];
    }
    else {
        [parameters setObject:(id)kCFBooleanFalse forKey:kSecAttrIsPermanent];
    }
    
    CFErrorRef cferror = NULL;
    SecKeyRef skey = SecKeyGenerateSymmetric((CFDictionaryRef)parameters, &cferror);
    if (skey == NULL) {
        LKKCReportError((OSStatus)CFErrorGetCode(cferror), NULL, @"Can't generate symmetric key");
        return nil;
    }
#endif
    LKKCKey *key = [LKKCKey keyWithSecKey:skey];
    CFRelease(skey);
    return key;    
}

- (LKKCKey *)generateAESKey
{
    unsigned int keySize = _keySize;    
    if (keySize == 0)
        keySize = kSecAES128;
    if (keySize != kSecAES128 && keySize != kSecAES192 && keySize != kSecAES256) {
        LKKCReportError(errSecParam, NULL, @"Invalid key size");
        return nil;
    }
    return [self _generateSymmetricKeyWithAlgorithm:kSecAttrKeyTypeAES keySize:keySize];
}

- (LKKCKey *)generate3DESKey
{
    unsigned int keySize = _keySize;    
    if (keySize == 0)
        keySize = kSec3DES192;
    if (keySize != kSec3DES192) {
        LKKCReportError(errSecParam, NULL, @"Invalid key size");
        return nil;
    }
    return [self _generateSymmetricKeyWithAlgorithm:kSecAttrKeyType3DES keySize:keySize];
}

@end