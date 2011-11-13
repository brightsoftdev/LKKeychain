//
//  LKKCKey.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKey.h"
#import "LKKCKeychainItem+Subclasses.h"
#import "LKKCUtil.h"

@interface LKKCKey()
- (BOOL)_getBooleanAttribute:(CFTypeRef)attribute flag:(CSSM_KEYATTR_FLAGS)flag use:(CSSM_KEYUSE)use;
- (BOOL)_getCSSMKeySize:(CSSM_KEY_SIZE_PTR)keySize;
@end

@implementation LKKCKey

+ (void)load
{
    if (self != [LKKCKey class])
        return;
    [LKKCKeychainItem registerSubclass:self];
}

+ (CFTypeRef)itemClass
{
    return kSecClassKey;
}

- (NSString *)label
{
    return [self valueForAttribute:kSecAttrLabel];
}

- (void)setLabel:(NSString *)label
{
    [self setAttribute:kSecAttrLabel toValue:label];
}

- (LKKCKeyClass)keyClass
{
    SecKeyRef skey = self.SecKey;
    if (skey == NULL)
        return LKKCKeyClassUnknown;
    CFTypeRef value = (CFTypeRef)[self valueForAttribute:kSecAttrKeyClass];
    if (value == kSecAttrKeyClassSymmetric)
        return LKKCKeyClassSymmetric;
    if (value == kSecAttrKeyClassPublic)
        return LKKCKeyClassPublic;
    if (value == kSecAttrKeyClassPrivate)
        return LKKCKeyClassPrivate;
    if (value != NULL) // CSSM_KEYCLASS value as a string in "%d" format
        return LKKCKeyClassUnknown;

    const CSSM_KEY *cssmkey;
    OSStatus status = SecKeyGetCSSMKey(skey, &cssmkey);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get CSSM key");
        return LKKCKeyClassUnknown;
    }
    
    switch (cssmkey->KeyHeader.KeyClass) {
        case CSSM_KEYCLASS_PUBLIC_KEY:
            return LKKCKeyClassPublic;
        case CSSM_KEYCLASS_PRIVATE_KEY:
            return LKKCKeyClassPrivate;
        case CSSM_KEYCLASS_SESSION_KEY:
            return LKKCKeyClassSymmetric;
        case CSSM_KEYCLASS_SECRET_PART:
        case CSSM_KEYCLASS_OTHER:
        default:
            return LKKCKeyClassUnknown;
    }
}

- (CSSM_ALGORITHMS)keyType
{
    SecKeyRef skey = self.SecKey;
    if (skey == NULL)
        return CSSM_ALGID_NONE;
    NSNumber *value = (NSNumber *)[self valueForAttribute:kSecAttrKeyType];
    if (value != NULL) // CSSM_ALGORITHM value as a CFString in "%d" format
        return [value intValue];

    const CSSM_KEY *cssmkey;
    OSStatus status = SecKeyGetCSSMKey(skey, &cssmkey);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get CSSM key");
        return CSSM_ALGID_NONE;
    }
    
    return cssmkey->KeyHeader.AlgorithmId;
}

- (BOOL)_getBooleanAttribute:(CFTypeRef)attribute flag:(CSSM_KEYATTR_FLAGS)flag use:(CSSM_KEYUSE)use
{
    CFBooleanRef value = (CFBooleanRef)[self valueForAttribute:attribute];
    if (value == kCFBooleanTrue)
        return YES;
    if (value == kCFBooleanFalse)
        return NO;
    
    SecKeyRef skey = self.SecKey;
    if (skey == NULL)
        return NO;
    
    const CSSM_KEY *cssmkey;
    OSStatus status = SecKeyGetCSSMKey(skey, &cssmkey);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get CSSM key");
        return NO;
    }
    
    if (flag != 0)
        return (cssmkey->KeyHeader.KeyAttr & flag) != 0;
    else if (use != 0)
        return (cssmkey->KeyHeader.KeyUsage & use) != 0;
    return NO;
}

- (BOOL)isPermanent
{
    return [self _getBooleanAttribute:kSecAttrIsPermanent flag:CSSM_KEYATTR_PERMANENT use:0];
}

- (BOOL)canEncrypt
{
    return [self _getBooleanAttribute:kSecAttrCanEncrypt flag:0 use:CSSM_KEYUSE_ENCRYPT];
}

- (BOOL)canDecrypt
{
    return [self _getBooleanAttribute:kSecAttrCanDecrypt flag:0 use:CSSM_KEYUSE_DECRYPT];
}

- (BOOL)canDerive
{
    return [self _getBooleanAttribute:kSecAttrCanDerive flag:0 use:CSSM_KEYUSE_DERIVE];
}

- (BOOL)canSign
{
    return [self _getBooleanAttribute:kSecAttrCanSign flag:0 use:CSSM_KEYUSE_SIGN];
}

- (BOOL)canVerify
{
    return [self _getBooleanAttribute:kSecAttrCanVerify flag:0 use:CSSM_KEYUSE_VERIFY];
}

- (BOOL)canWrap
{
    return [self _getBooleanAttribute:kSecAttrCanWrap flag:0 use:CSSM_KEYUSE_WRAP];
}

- (BOOL)canUnwrap
{
    return [self _getBooleanAttribute:kSecAttrCanUnwrap flag:0 use:CSSM_KEYUSE_UNWRAP];
}

- (BOOL)_getCSSMKeySize:(CSSM_KEY_SIZE_PTR)keySize
{
    SecKeyRef skey = self.SecKey;
    if (skey == NULL)
        return NO;
    
    CSSM_CSP_HANDLE cspHandle;
    OSStatus status = SecKeyGetCSPHandle(skey, &cspHandle);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get CSP handle");
        return NO;
    }
    
    const CSSM_KEY *cssmkey;
    status = SecKeyGetCSSMKey(skey, &cssmkey);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get CSSM key");
        return NO;
    }
    
    status = CSSM_QueryKeySizeInBits(cspHandle, 0, cssmkey, keySize);
    if (status != CSSM_OK) {
        LKKCReportError(status, NULL, @"Can't get key size");
        return NO;
    }
    
    return YES;
}

- (int)keySize
{
    NSNumber *value = [self valueForAttribute:kSecAttrKeySizeInBits];
    if (value != nil)
        return [value intValue];
    
    SecKeyRef skey = self.SecKey;
    if (skey == NULL)
        return 0;

    const CSSM_KEY *cssmkey;
    OSStatus status = SecKeyGetCSSMKey(skey, &cssmkey);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get CSSM key");
        return 0;
    }
    
    return cssmkey->KeyHeader.LogicalKeySizeInBits;
}

- (int)effectiveKeySize
{
    NSNumber *value = [self valueForAttribute:kSecAttrEffectiveKeySize];
    if (value != nil)
        return [value intValue];

    SecKeyRef skey = self.SecKey;
    if (skey == NULL)
        return self.keySize;
    
    CSSM_CSP_HANDLE cspHandle;
    OSStatus status = SecKeyGetCSPHandle(skey, &cspHandle);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get CSP handle");
        return self.keySize;
    }
    
    const CSSM_KEY *cssmkey;
    status = SecKeyGetCSSMKey(skey, &cssmkey);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get CSSM key");
        return self.keySize;
    }
    
    CSSM_KEY_SIZE keySize;
    status = CSSM_QueryKeySizeInBits(cspHandle, 0, cssmkey, &keySize);
    if (status != CSSM_OK) {
        LKKCReportError(status, NULL, @"Can't get key size");
        return self.keySize;
    }
    
    return keySize.EffectiveKeySizeInBits;
}

- (SecKeyRef)SecKey
{
    return (SecKeyRef)_sitem;
}

@end
