//
//  LKKCKey.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
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

#import "LKKCKey.h"
#import "LKKCKeychain.h"
#import "LKKCKeychainItem+Subclasses.h"
#import "LKKCUtil.h"
#import "LKKCCryptoContext.h"

@interface LKKCKey()
+ (NSString *)stringFromKeyType:(LKKCKeyType)keyType;
+ (NSString *)stringFromKeyClass:(LKKCKeyClass)keyClass;

- (BOOL)_getBooleanAttribute:(CFTypeRef)attribute flag:(CSSM_KEYATTR_FLAGS)flag use:(CSSM_KEYUSE)use;
@end

static NSString *LKKCAttrKeyID = @"LKKCKeyID";

@implementation LKKCKey

+ (CFTypeRef)_algorithmFromLKKCKeyType:(LKKCKeyType)keyType
{
    switch (keyType) {
        case LKKCKeyTypeRSA:
            return kSecAttrKeyTypeRSA;
        case LKKCKeyTypeDSA:
            return kSecAttrKeyTypeDSA;
        case LKKCKeyTypeAES:
            return kSecAttrKeyTypeAES;
        case LKKCKeyTypeDES:
            return kSecAttrKeyTypeDES;
        case LKKCKeyType3DES:
            return kSecAttrKeyType3DES;
        case LKKCKeyTypeRC4:
            return kSecAttrKeyTypeRC4;
        case LKKCKeyTypeRC2:
            return kSecAttrKeyTypeRC2;
        case LKKCKeyTypeCAST:
            return kSecAttrKeyTypeCAST;
        case LKKCKeyTypeECDSA:
            return kSecAttrKeyTypeECDSA;
        case LKKCKeyTypeUnknown:
        default:
            return NULL;
    }
}

+ (CSSM_ALGORITHMS)_cssmAlgorithmFromLKKCKeyType:(LKKCKeyType)keyType
{
    switch (keyType) {
        case LKKCKeyTypeRSA:
            return CSSM_ALGID_RSA;
        case LKKCKeyTypeDSA:
            return CSSM_ALGID_DSA;
        case LKKCKeyTypeAES:
            return CSSM_ALGID_AES;
        case LKKCKeyTypeDES:
            return CSSM_ALGID_DES;
        case LKKCKeyType3DES:
            return CSSM_ALGID_3DES_3KEY_EDE; // Not CSSM_ALGID_3DES!
        case LKKCKeyTypeRC4:
            return CSSM_ALGID_RC4;
        case LKKCKeyTypeRC2:
            return CSSM_ALGID_RC2;
        case LKKCKeyTypeCAST:
            return CSSM_ALGID_CAST;
        case LKKCKeyTypeECDSA:
            return CSSM_ALGID_ECDSA;
        case LKKCKeyTypeUnknown:
        default:
            return CSSM_ALGID_NONE;
    }

}

+ (LKKCKeyType)_keyTypeFromAlgorithm:(CFTypeRef)algorithm
{
    if (CFEqual(algorithm, kSecAttrKeyTypeRSA))
        return LKKCKeyTypeRSA;
    if (CFEqual(algorithm, kSecAttrKeyTypeDSA))
        return LKKCKeyTypeDSA;
    if (CFEqual(algorithm, kSecAttrKeyTypeAES))
        return LKKCKeyTypeAES;
    if (CFEqual(algorithm, kSecAttrKeyTypeDES))
        return LKKCKeyTypeDES;
    if (CFEqual(algorithm, kSecAttrKeyType3DES) || CFEqual(algorithm, CFSTR("17"))) // CSSM_ALGID_3DES_3KEY_EDE
        return LKKCKeyType3DES;
    if (CFEqual(algorithm, kSecAttrKeyTypeRC4))
        return LKKCKeyTypeRC4;
    if (CFEqual(algorithm, kSecAttrKeyTypeRC2))
        return LKKCKeyTypeRC2;
    if (CFEqual(algorithm, kSecAttrKeyTypeCAST))
        return LKKCKeyTypeCAST;
    if (CFEqual(algorithm, kSecAttrKeyTypeECDSA))
        return LKKCKeyTypeECDSA;
    return LKKCKeyTypeUnknown;
}

+ (LKKCKeyType)_keyTypeFromCSSMAlgorithm:(CSSM_ALGORITHMS)algorithm
{
    switch (algorithm) {
        case CSSM_ALGID_RSA:
            return LKKCKeyTypeRSA;
        case CSSM_ALGID_DSA:
            return LKKCKeyTypeDSA;
        case CSSM_ALGID_AES:
            return LKKCKeyTypeAES;
        case CSSM_ALGID_DES:
            return LKKCKeyTypeDES;
        case CSSM_ALGID_3DES:
        case CSSM_ALGID_3DES_3KEY_EDE:
            return LKKCKeyType3DES;
        case CSSM_ALGID_RC4:
            return LKKCKeyTypeRC4;
        case CSSM_ALGID_RC2:
            return LKKCKeyTypeRC2;
        case CSSM_ALGID_CAST:
            return LKKCKeyTypeCAST;
        case CSSM_ALGID_ECDSA:
            return LKKCKeyTypeECDSA;
        default:
            return LKKCKeyTypeUnknown;
    }
}

+ (NSString *)stringFromKeyType:(LKKCKeyType)keyType
{
    switch (keyType) {
        case LKKCKeyTypeRSA:
            return @"RSA";
        case LKKCKeyTypeDSA:
            return @"DSA";
        case LKKCKeyTypeAES:
            return @"AES";
        case LKKCKeyTypeDES:
            return @"DES";
        case LKKCKeyType3DES:
            return @"3DES";
        case LKKCKeyTypeRC4:
            return @"RC4";
        case LKKCKeyTypeRC2:
            return @"RC2";
        case LKKCKeyTypeCAST:
            return @"CAST";
        case LKKCKeyTypeECDSA:
            return @"ECDSA";
        case LKKCKeyTypeUnknown:
        default:
            return @"unknown";
    }
}

+ (NSString *)stringFromKeyClass:(LKKCKeyClass)keyClass
{
    switch (keyClass) {
        case LKKCKeyClassPublic:
            return @"public";
        case LKKCKeyClassPrivate:
            return @"private";
        case LKKCKeyClassSymmetric:
            return @"symmetric";
        case LKKCKeyClassUnknown:
        default:
            return @"unknown";
    }
}

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

+ (LKKCKey *)keyWithSecKey:(SecKeyRef)skey
{
    return [[[LKKCKey alloc] initWithSecKeychainItem:(SecKeychainItemRef)skey attributes:nil] autorelease];
}

+ (LKKCKey *)keyWithData:(NSData *)data 
                keyClass:(LKKCKeyClass)keyClass
                 keyType:(LKKCKeyType)keyType 
                 keySize:(UInt32)keySize
{
    NSMutableDictionary *parameters = [NSMutableDictionary dictionary];
    
    CFTypeRef skeyType = [[self class] _algorithmFromLKKCKeyType:keyType];
    if (skeyType == NULL) {
        LKKCReportError(errSecParam, NULL, @"Invalid key type");
        return nil;
    }
    [parameters setObject:skeyType forKey:kSecAttrKeyType];
    
    CFTypeRef skeyClass = NULL;
    switch (keyClass) {
        case LKKCKeyClassPublic:
            skeyClass = kSecAttrKeyClassPublic;
            break;
        case LKKCKeyClassPrivate:
            skeyClass = kSecAttrKeyClassPrivate;
            break;
        case LKKCKeyClassSymmetric:
            skeyClass = kSecAttrKeyClassSymmetric;
            break;
        case LKKCKeyClassUnknown:
        default:
            LKKCReportError(errSecParam, NULL, @"Invalid key class");
            return nil;
    }
    [parameters setObject:skeyClass forKey:kSecAttrKeyClass];
    
    [parameters setObject:[NSNumber numberWithInt:keySize] forKey:kSecAttrKeySizeInBits];
    
    CFErrorRef error = NULL;
    SecKeyRef skey = SecKeyCreateFromData((CFDictionaryRef)parameters, (CFDataRef)data, &error);
    if (skey == NULL) {
        LKKCReportError((OSStatus)CFErrorGetCode(error), NULL, @"Can't create key");
        CFRelease(error);
        return nil;
    }
    LKKCKey *key = [LKKCKey keyWithSecKey:skey];
    CFRelease(skey);
    return key;
}

- (NSString *)description
{
    NSMutableString *result = [NSMutableString string];
    [result appendFormat:@"<%@ %p %d-bit %@ %@", [self className], self, self.keySize,
     [[self class] stringFromKeyClass:self.keyClass],
     [[self class] stringFromKeyType:self.keyType]];
    NSString *label = self.label;
    if (label != nil) {
        [result appendFormat:@" '%@'", label];
    }
    [result appendString:@">"];
    return result;
}

- (NSString *)label
{
    return [self valueForAttribute:kSecAttrLabel];
}

- (void)setLabel:(NSString *)label
{
    [self setAttribute:kSecAttrLabel toValue:label];
}

- (NSData *)keyID
{
    NSData *value = [self valueForAttribute:LKKCAttrKeyID];
    if (value != nil)
        return value;
    
    UInt32 tags[] = { kSecKeyLabel };
    UInt32 formats[] = { CSSM_DB_ATTRIBUTE_FORMAT_BLOB };
    SecKeychainAttributeInfo info = { .count = 1, .tag = tags, .format = formats };
    SecKeychainAttributeList *attrList;
    OSStatus status = SecKeychainItemCopyAttributesAndData(_sitem, &info, NULL, &attrList, NULL, NULL);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get kSecKeyLabel attribute");
        return nil;
    }
    if (attrList->count == 1 && attrList->attr[0].tag == kSecKeyLabel) {
        value = [NSData dataWithBytes:attrList->attr[0].data length:attrList->attr[0].length];
        [_attributes setObject:value forKey:LKKCAttrKeyID];
    }
    SecKeychainItemFreeAttributesAndData(attrList, NULL);
    
    return value;
}

- (void)setKeyID:(NSData *)keyID
{
    [self setAttribute:LKKCAttrKeyID toValue:keyID];
    [_attributes removeObjectForKey:kSecAttrApplicationLabel];
    [_updatedAttributes removeObjectForKey:kSecAttrApplicationLabel];
}

- (NSString *)applicationLabel
{
    return [self valueForAttribute:kSecAttrApplicationLabel];
}

- (void)setApplicationLabel:(NSString *)applicationLabel
{
    [self setAttribute:kSecAttrApplicationLabel toValue:applicationLabel];
    [_attributes removeObjectForKey:LKKCAttrKeyID];
    [_updatedAttributes removeObjectForKey:LKKCAttrKeyID];
}

- (NSString *)tag
{
    return [self valueForAttribute:kSecAttrApplicationTag];
}

- (void)setTag:(NSString *)tag
{
    [self setAttribute:kSecAttrApplicationTag toValue:tag];
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

- (LKKCKeyType)keyType
{
    SecKeyRef skey = self.SecKey;
    if (skey == NULL)
        return LKKCKeyTypeUnknown;
    CFTypeRef value = (CFTypeRef)[self valueForAttribute:kSecAttrKeyType];

    // value is a CSSM_ALGORITHM value as a CFString in "%d" format
    if (value != NULL)
        return [[self class] _keyTypeFromAlgorithm:value];

    const CSSM_KEY *cssmkey;
    OSStatus status = SecKeyGetCSSMKey(skey, &cssmkey);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get CSSM key");
        return LKKCKeyTypeUnknown;
    }
    
    return [[self class] _keyTypeFromCSSMAlgorithm:cssmkey->KeyHeader.AlgorithmId];
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
        return (cssmkey->KeyHeader.KeyUsage & (use | CSSM_KEYUSE_ANY)) != 0;
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

- (NSData *)keyDataWithError:(NSError **)error
{
    SecExternalFormat format;
    switch (self.keyClass) {
        case LKKCKeyClassSymmetric:
            format = kSecFormatRawKey;
            break;
        case LKKCKeyClassPublic:
            format = kSecFormatOpenSSL;
            break;
        case LKKCKeyClassPrivate:
            format = kSecFormatOpenSSL;
            break;
        default:
            LKKCReportError(errSecInvalidKeyRef, error, @"Invalid key class");
            return nil;
    }

    OSStatus status;
    if (SecItemExport != NULL) {
        SecItemImportExportFlags flags = 0;
        SecItemImportExportKeyParameters params;
        bzero(&params, sizeof(params));
        params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;

        NSData *data = nil;
        status = SecItemExport(_sitem, format, flags, &params, (CFDataRef *)&data);
        if (status) {
            LKKCReportError(status, error, @"Can't export key");
            return nil;
        }
        return [data autorelease];
    }
    else {
        SecItemImportExportFlags flags = 0;
        SecKeyImportExportParameters params;
        bzero(&params, sizeof(params));
        params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
        
        NSData *data = nil;
        status = SecKeychainItemExport(_sitem, format, flags, &params, (CFDataRef *)&data);
        if (status) {
            LKKCReportError(status, error, @"Can't export key");
            return nil;
        }
        return [data autorelease];
    }
}

- (SecAccessRef)access
{
    SecAccessRef saccess = NULL;
    OSStatus status = SecAccessCreate((CFStringRef)self.label, NULL /* current app */, &saccess);
    if (status) {
        LKKCReportError(status, NULL, @"Can't create access object for newly generated key");
        return nil;
    }
    [(id)saccess autorelease];
    return saccess;
}

- (BOOL)saveItemWithError:(NSError **)error
{
    if (_sitem == nil) {
        [NSException raise:NSInvalidArgumentException format:@"Can't save items that aren't on a keychain"];
    }

    int oldAttrCount = 0;
    SecKeychainAttribute oldAttrs[3];
    
    NSData *keyID = [_updatedAttributes objectForKey:LKKCAttrKeyID];
    if (keyID != nil) {
        oldAttrs[oldAttrCount].tag = kSecKeyLabel;
        oldAttrs[oldAttrCount].length = (UInt32)[keyID length];
        oldAttrs[oldAttrCount].data = (void *)[keyID bytes];
        oldAttrCount++;
    }
    
    // SecItemUpdate can't modify kSecAttrApplicationLabel. It returns an invalid attribute error.
    NSString *applicationLabel = [_updatedAttributes objectForKey:kSecAttrApplicationLabel];
    if (keyID == nil && applicationLabel != nil) {
        const char *utf8String = [applicationLabel UTF8String];
        oldAttrs[oldAttrCount].tag = kSecKeyLabel;
        oldAttrs[oldAttrCount].length = (UInt32)strlen(utf8String);
        oldAttrs[oldAttrCount].data = (void *)utf8String;
        oldAttrCount++;
    }
    
    // SecItemUpdate can't modify kSecAttrApplicationTag. It modifies kSecAttrLabel instead.
    NSString *applicationTag = [_updatedAttributes objectForKey:kSecAttrApplicationTag];
    if (applicationTag != nil) {
        const char *utf8String = [applicationTag UTF8String];
        oldAttrs[oldAttrCount].tag = kSecKeyApplicationTag;
        oldAttrs[oldAttrCount].length = (UInt32)strlen(utf8String);
        oldAttrs[oldAttrCount].data = (void *)utf8String;
        oldAttrCount++;
    }
    
    if (oldAttrCount > 0) {
        SecKeychainAttributeList attrList;
        attrList.count = oldAttrCount;
        attrList.attr = oldAttrs;
        OSStatus status = SecKeychainItemModifyAttributesAndData(_sitem, &attrList, 0, NULL);
        if (status) {
            LKKCReportError(status, error, @"Can't modify item attributes");
            return NO;
        }
    }
    if (keyID != nil) {
        [_updatedAttributes removeObjectForKey:keyID];
    }
    if (applicationLabel != nil) {
        [_updatedAttributes removeObjectForKey:kSecAttrApplicationLabel];        
    }
    if (applicationTag != nil) {
        [_updatedAttributes removeObjectForKey:kSecAttrApplicationTag];
    }
    
    return [super saveItemWithError:error];
}

#pragma mark - Operations

- (size_t)blockSize
{
    switch (self.keyType) {
        case LKKCKeyTypeAES:
            return 16;
        case LKKCKeyTypeDES:
        case LKKCKeyType3DES:
        case LKKCKeyTypeCAST:
        case LKKCKeyTypeRC2:
            return 8;
        case LKKCKeyTypeRC4:
            return 1;
        case LKKCKeyTypeDSA:
        case LKKCKeyTypeECDSA:
        case LKKCKeyTypeRSA:
        default:
            // BUG: SecKeyGetBlockSize returns the logical key size in bits, not the bock size in bytes.
            return (SecKeyGetBlockSize(self.SecKey) + 7) / 8;
    }
}

- (NSData *)randomInitVector
{
    size_t blockSize = self.blockSize;
    if (blockSize < 2 || self.keyClass != LKKCKeyClassSymmetric)
        return nil;
    char *buf[blockSize];
    arc4random_buf(&buf, blockSize);
    return [NSData dataWithBytes:buf length:blockSize];
}

- (NSData *)encryptData:(NSData *)plaintext initVector:(NSData *)iv error:(NSError **)error
{
    NSData *result = nil;
    @autoreleasepool {
        LKKCCryptoContext *cc = [LKKCCryptoContext cryptoContextForKey:self
                                                             operation:CSSM_ACL_AUTHORIZATION_ENCRYPT
                                                            initVector:iv 
                                                                 error:error];
        if (cc == nil)
            return nil;
        result = [[cc encryptData:plaintext error:error] retain];
    }
    return [result autorelease];
}

- (NSData *)decryptData:(NSData *)ciphertext initVector:(NSData *)iv error:(NSError **)error
{
    NSData *result = nil;
    @autoreleasepool {
        LKKCCryptoContext *cc = [LKKCCryptoContext cryptoContextForKey:self
                                                             operation:CSSM_ACL_AUTHORIZATION_DECRYPT
                                                            initVector:iv 
                                                                 error:error];
        if (cc == nil)
            return nil;
        result = [[cc decryptData:ciphertext error:error] retain];
    }
    return [result autorelease];
}

@end
