//
//  LKKCCryptoContext.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-15.
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

#import "LKKCCryptoContext.h"
#import "LKKCKey.h"
#import "LKKCUtil.h"

@interface LKKCCryptoContext()
- (id)initWithKey:(LKKCKey *)key initVector:(NSData *)iv ccHandle:(CSSM_CC_HANDLE)cchandle;
@end

@implementation LKKCCryptoContext

+ (LKKCCryptoContext *)cryptoContextForKey:(LKKCKey *)key 
                                 operation:(CSSM_ACL_AUTHORIZATION_TAG)operation 
                                initVector:(NSData *)iv
                                     error:(NSError **)error
{
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
    
    CSSM_ENCRYPT_MODE algmode = CSSM_ALGMODE_NONE;
    CSSM_PADDING padding = CSSM_PADDING_NONE;
    switch(algid) {
            /* 8-byte block ciphers */
        case CSSM_ALGID_DES:
        case CSSM_ALGID_3DES_3KEY_EDE:
        case CSSM_ALGID_RC5:
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
        case CSSM_ALGID_ASC:
        case CSSM_ALGID_RC4:
            algmode = CSSM_ALGMODE_NONE;
            padding = CSSM_PADDING_NONE;
            break;
            
        case CSSM_ALGID_RSA:
            padding = CSSM_PADDING_PKCS1;
            break;
        default:
            LKKCReportError(errSecInvalidAlgorithm, error, @"Unsupported key type");
            return nil;
    }
    
    CSSM_CC_HANDLE cchandle = 0;
    switch (key.keyClass) {
        case LKKCKeyClassPublic:
        case LKKCKeyClassPrivate: {
            status = CSSM_CSP_CreateAsymmetricContext(csphandle, algid, scredentials, cssmkey, padding, &cchandle);
            if (status) {
                LKKCReportError(status, error, @"Can't create symmetric context");
                return nil;
            }
            break;            
        }
        case LKKCKeyClassSymmetric: {
            if (iv == nil) {
                LKKCReportError(errSecParam, error, @"Missing initialization vector");
                return nil;
            }
            CSSM_DATA cssm_iv = { .Length = [iv length], .Data = (void *)[iv bytes] };
            status = CSSM_CSP_CreateSymmetricContext(csphandle, algid, algmode, scredentials, cssmkey, &cssm_iv, padding, NULL, &cchandle);
            if (status) {
                LKKCReportError(status, error, @"Can't create symmetric context");
                return nil;
            }
            break;
        }
        case LKKCKeyClassUnknown:
        default: {
            LKKCReportError(errSecParam, error, @"Invalid key class");
            return nil;
        }
    }
    
    return [[[LKKCCryptoContext alloc] initWithKey:key initVector:iv ccHandle:cchandle] autorelease];    
}

- (id)initWithKey:(LKKCKey *)key initVector:(NSData *)iv ccHandle:(CSSM_CC_HANDLE)cchandle
{
    self = [super init];
    if (self == nil)
        return nil;
    _key = [key retain];
    _iv = [iv retain];
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
