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
#import "LKKCKeychainItem+Subclasses.h"
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
    NSData *_keyID;
    NSString *_applicationLabel;
    NSString *_tag;
    BOOL _extractable;
}
@synthesize keySize = _keySize;
@synthesize keychain = _keychain;
@synthesize label = _label;
@synthesize keyID = _keyID;
@synthesize applicationLabel = _applicationLabel;
@synthesize tag = _tag;
@synthesize extractable = _extractable;

+ (LKKCKeyGenerator *)generator
{
    return [[[LKKCKeyGenerator alloc] init] autorelease];
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
    if (_extractable || _keychain == nil) {
        // SecKeyGenerateSymmetric can only create non-extractable keys.
        // When the user requested an extractable key or when we create a floating key,
        // use the older SecKeyGenerate instead.
        SecKeychainRef skeychain = NULL;
        if (_keychain != nil)
            skeychain = _keychain.SecKeychain;
        
        CSSM_ALGORITHMS algid = (CSSM_ALGORITHMS)[(id)algorithm integerValue];
        
        CSSM_KEYUSE keyUse = CSSM_KEYUSE_ANY | CSSM_KEYUSE_ENCRYPT | CSSM_KEYUSE_DECRYPT | CSSM_KEYUSE_WRAP | CSSM_KEYUSE_UNWRAP | CSSM_KEYUSE_SIGN | CSSM_KEYUSE_VERIFY;
        
        CSSM_KEYATTR_FLAGS keyAttr = CSSM_KEYATTR_RETURN_DEFAULT | CSSM_KEYATTR_EXTRACTABLE;
        
        SecAccessRef saccess = NULL;
        OSStatus status = SecAccessCreate((CFStringRef)_label, NULL /* current app */, &saccess);
        if (status) {
            LKKCReportError(status, NULL, @"Can't create access object for newly generated key");
            return nil;
        }
        SecKeyRef skey = NULL;
        status = SecKeyGenerate(skeychain, algid, keySize, 0, keyUse, keyAttr, saccess, &skey);
        CFRelease(saccess);
        if (status) {
            LKKCReportError(status, NULL, @"Can't generate symmetric key");
            return nil;
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
        
        SecAccessRef saccess = NULL;
        OSStatus status = SecAccessCreate((CFStringRef)_label, NULL /* current app */, &saccess);
        if (status) {
            LKKCReportError(status, NULL, @"Can't create access object for newly generated key");
            return nil;
        }
        [parameters setObject:(id)saccess forKey:kSecAttrAccess];
        CFRelease(saccess);

        CFErrorRef cferror = NULL;
        SecKeyRef skey = SecKeyGenerateSymmetric((CFDictionaryRef)parameters, &cferror);
        if (skey == NULL) {
            LKKCReportError((OSStatus)CFErrorGetCode(cferror), NULL, @"Can't generate symmetric key");
            return nil;
        }

        LKKCKey *key = [LKKCKeychainItem itemWithClass:kSecClassKey
                                       SecKeychainItem:(SecKeychainItemRef)skey 
                                            attributes:nil];
        CFRelease(skey);
        
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
