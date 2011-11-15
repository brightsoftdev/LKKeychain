//
//  LKKCCryptoContext.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-15.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCCryptoContext.h"
#import "LKKCKey.h"
#import "LKKCUtil.h"

static uint8 iv[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
static const CSSM_DATA ivCommon = { .Length = 16, .Data = iv};

@interface LKKCCryptoContext()
- (id)initWithKey:(LKKCKey *)key ccHandle:(CSSM_CC_HANDLE)cchandle;
@end

@implementation LKKCCryptoContext
{
    LKKCKey *_key;
    CSSM_CC_HANDLE _cchandle;
}

+ (LKKCCryptoContext *)cryptoContextForKey:(LKKCKey *)key operation:(CSSM_ACL_AUTHORIZATION_TAG)operation error:(NSError **)error
{
    if (key == nil) {
        LKKCReportError(errSecParam, error, @"Key must not be nil");
        return nil;
    }
    if (key.keyClass != LKKCKeyClassSymmetric) { // TODO
        LKKCReportError(errSecUnimplemented, error, @"Only symmetric keys are supported for now");
        return nil;
    }
    
    SecKeyRef skey = key.SecKey;
    if (skey == nil) {
        LKKCReportError(errSecInvalidKeyRef, error, @"Key has been deleted");
        return nil;
    }

    CSSM_CSP_HANDLE csphandle = 0;
    OSStatus status = SecKeyGetCSPHandle(skey, &csphandle);
    if (status) {
        LKKCReportError(status, error, @"Can't get CSP handle");
        return nil;
    }
    
    const CSSM_KEY *cssmkey = NULL;
    status = SecKeyGetCSSMKey(skey, &cssmkey);
    if (status) {
        LKKCReportError(status, error, @"Can't get CSSM key");
        return nil;
    }
    
    const CSSM_ACCESS_CREDENTIALS *scredentials = NULL;
    status = SecKeyGetCredentials(skey, operation, kSecCredentialTypeDefault, &scredentials);
    if (status) {
        LKKCReportError(status, error, @"Can't get credentials");
        return nil;
    }
    
    CSSM_ALGORITHMS algid = cssmkey->KeyHeader.AlgorithmId;
    if (algid == CSSM_ALGID_3DES)
        algid = CSSM_ALGID_3DES_3KEY_EDE;
    
    CSSM_ENCRYPT_MODE algmode;
    CSSM_PADDING padding;
    switch(algid) {
            /* 8-byte block ciphers */
        case CSSM_ALGID_DES:
        case CSSM_ALGID_3DES_3KEY_EDE:
        case CSSM_ALGID_RC2:
            algmode = CSSM_ALGMODE_CBCPadIV8;
            padding = CSSM_PADDING_PKCS5;
            break;
            
            /* 16-byte block ciphers */
        case CSSM_ALGID_AES:
            algmode = CSSM_ALGMODE_CBCPadIV8;
            padding = CSSM_PADDING_PKCS7;
            break;
            
            /* stream ciphers */
        case CSSM_ALGID_RC4:
            algmode = CSSM_ALGMODE_NONE;
            padding = CSSM_PADDING_NONE;
            break;
            
        default:
            LKKCReportError(errSecInvalidAlgorithm, error, @"Unsupported key type");
            return nil;
    }
    
    CSSM_CC_HANDLE cchandle = 0;
    status = CSSM_CSP_CreateSymmetricContext(csphandle, algid, algmode, scredentials, cssmkey, &ivCommon, padding, NULL, &cchandle);
    if (status) {
        LKKCReportError(status, error, @"Can't create symmetric context");
        return nil;
    }

    return [[[LKKCCryptoContext alloc] initWithKey:key ccHandle:cchandle] autorelease];
}

- (id)initWithKey:(LKKCKey *)key ccHandle:(CSSM_CC_HANDLE)cchandle
{
    self = [super init];
    if (self == nil)
        return nil;
    _key = [key retain];
    _cchandle = cchandle;
    return self;
}

- (void)dealloc
{
    CSSM_DeleteContext(_cchandle);
    [_key release];
    [super dealloc];
}

- (NSData *)encryptData:(NSData *)plaintext error:(NSError **)error
{
    NSData *result = nil;
    CSSM_DATA input = { .Length = [plaintext length], .Data = (void *)[plaintext bytes] };
    CSSM_DATA output = { .Length = 0, .Data = NULL };
    CSSM_DATA remData = { .Length = 0, .Data = NULL };
    CSSM_SIZE bytesEncrypted = 0;
    OSStatus status = CSSM_EncryptData(_cchandle, &input, 1, &output, 1, &bytesEncrypted, &remData);
    if (status) {
        LKKCReportError(status, error, @"Can't encrypt data");
        goto exit;
    }
    if (remData.Length != 0) {
        LKKCReportError(errSecInternalError, error, @"Leftover data after encryption");
        goto exit;
    }
    
    result = [NSData dataWithBytesNoCopy:output.Data length:bytesEncrypted freeWhenDone:YES];
    output.Data = NULL;
    
exit:
    if (output.Data != NULL)
        free(output.Data);
    if (remData.Data != NULL)
        free(remData.Data);
    return result;
}

- (NSData *)decryptData:(NSData *)ciphertext error:(NSError **)error
{
    NSData *result = nil;
    CSSM_DATA input = { .Length = [ciphertext length], .Data = (void *)[ciphertext bytes] };
    CSSM_DATA output = { .Length = 0, .Data = NULL };
    CSSM_DATA remData = { .Length = 0, .Data = NULL };
    CSSM_SIZE bytesDecrypted = 0;
    
    OSStatus status = CSSM_DecryptData(_cchandle, &input, 1, &output, 1, &bytesDecrypted, &remData);
    if (status) {
        LKKCReportError(status, error, @"Can't decrypt data");
        goto exit;
    }
    if (remData.Length != 0) {
        LKKCReportError(errSecInternalError, error, @"Leftover data after decryption");
        goto exit;
    }
    
    result = [NSData dataWithBytesNoCopy:output.Data length:bytesDecrypted freeWhenDone:YES];
    output.Data = NULL;
    
exit:
    if (output.Data != NULL)
        free(output.Data);
    if (remData.Data != NULL)
        free(remData.Data);
    return result;
}

@end
