//
//  LKKCTrust.m
//  LKKeychain
//
//  Created by Károly Lőrentey on 2011-12-18.
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

#import "LKKCTrust.h"
#import "LKKCKeychain.h"
#import "LKKCKey.h"
#import "LKKCUtil.h"

@interface LKKCTrust()
- (id)initWithSecTrust:(SecTrustRef)strust;
+ (LKKCTrust *)trustForCertificateChain:(NSArray *)certificateChain policy:(SecPolicyRef)spolicy;
@end

@implementation LKKCTrust

#pragma mark - Lifecycle

- (id)initWithSecTrust:(SecTrustRef)strust
{
    self = [super init];
    if (self == nil)
        return nil;
    _strust = (SecTrustRef)CFRetain(strust);
    _anchors = nil;
    _systemAnchors = YES;
    return self;
}

- (void)dealloc
{
    CFRelease(_strust);
    [super dealloc];
}

+ (LKKCTrust *)trustForCertificateChain:(NSArray *)certificateChain policy:(SecPolicyRef)spolicy
{
    NSMutableArray *scertificateChain = [NSMutableArray arrayWithCapacity:[certificateChain count]];
    for (LKKCCertificate *certificate in certificateChain) {
        [scertificateChain addObject:(id)certificate.SecCertificate];
    }
    
    SecTrustRef strust = NULL;
    OSStatus status = SecTrustCreateWithCertificates((CFArrayRef)scertificateChain, spolicy, &strust);
    if (status) {
        LKKCReportError(status, NULL, @"Can't create trust reference");
        return nil;
    }
    LKKCTrust *trust = [[[LKKCTrust alloc] initWithSecTrust:strust] autorelease];
    CFRelease(strust);
    return trust;    
}

+ (LKKCTrust *)trustForBasicX509CertificateChain:(NSArray *)certificateChain
{
    SecPolicyRef spolicy = SecPolicyCreateBasicX509();
    if (spolicy == NULL)
        return nil;
    LKKCTrust *trust = [self trustForCertificateChain:certificateChain policy:spolicy];
    CFRelease(spolicy);
    return trust;
}

+ (LKKCTrust *)trustForSSLClientCertificateChain:(NSArray *)certificateChain hostname:(NSString *)hostname
{
    SecPolicyRef spolicy = SecPolicyCreateSSL(false, (CFStringRef)hostname);
    if (spolicy == NULL)
        return nil;
    LKKCTrust *trust = [self trustForCertificateChain:certificateChain policy:spolicy];
    CFRelease(spolicy);
    return trust;
}

+ (LKKCTrust *)trustForSSLServerCertificateChain:(NSArray *)certificateChain hostname:(NSString *)hostname
{
    SecPolicyRef spolicy = SecPolicyCreateSSL(true, (CFStringRef)hostname);
    if (spolicy == NULL)
        return nil;
    LKKCTrust *trust = [self trustForCertificateChain:certificateChain policy:spolicy];
    CFRelease(spolicy);
    return trust;
}

#pragma mark - Anchor certificates

- (NSArray *)anchors
{
    if (_systemAnchors && _anchors == nil)
        return [[self class] systemAnchors];
    if (!_systemAnchors)
        return _anchors;
    return [_anchors arrayByAddingObjectsFromArray:[[self class] systemAnchors]];
}

- (void)setAnchors:(NSArray *)anchors
{
    NSMutableArray *sanchors = [NSMutableArray arrayWithCapacity:[anchors count]];
    for (LKKCCertificate *certificate in anchors) {
        [sanchors addObject:(id)certificate.SecCertificate];
    }
    OSStatus status = SecTrustSetAnchorCertificates(_strust, (CFArrayRef)sanchors);
    if (status) { // unexpected
        LKKCReportError(status, NULL, @"Can't set anchor certificates");
        return;
    }
    
    if (_anchors == nil) {
        _anchors = [[NSMutableArray alloc] init];
    }
    else {
        [_anchors removeAllObjects];
    }
    [_anchors addObjectsFromArray:anchors];
    _systemAnchors = NO;
}

- (void)addCustomAnchors:(NSArray *)anchors
{
    NSMutableArray *sanchors = [NSMutableArray arrayWithCapacity:[_anchors count] + [anchors count]];
    for (LKKCCertificate *certificate in _anchors) {
        [sanchors addObject:(id)certificate.SecCertificate];
    }
    for (LKKCCertificate *certificate in anchors) {
        [sanchors addObject:(id)certificate.SecCertificate];
    }
    
    OSStatus status = SecTrustSetAnchorCertificates(_strust, (CFArrayRef)sanchors);
    if (status) { // unexpected
        LKKCReportError(status, NULL, @"Can't set anchor certificates");
        return;
    }
    status = SecTrustSetAnchorCertificatesOnly(_strust, _systemAnchors);
    if (status) { // unexpected
        LKKCReportError(status, NULL, @"Can't set trust state for system anchors");
        return;
    }

    if (_anchors == nil) {
        _anchors = [[NSMutableArray alloc] init];
        _systemAnchors = YES;
    }
    [_anchors addObjectsFromArray:anchors];
}

+ (NSArray *)systemAnchors
{
    NSArray *sanchors = NULL;
    OSStatus status = SecTrustCopyAnchorCertificates((CFArrayRef *)&sanchors);
    if (status) { // unexpected
        LKKCReportError(status, NULL, @"Can't get system anchor certificates");
        return nil;
    }
    NSMutableArray *anchors = [NSMutableArray arrayWithCapacity:[sanchors count]];
    for (id scert in sanchors) {
        [anchors addObject:[LKKCCertificate certificateWithSecCertificate:(SecCertificateRef)scert]];
    }
    [sanchors release];
    return anchors;
}

#pragma mark - Evaluation properties

- (void)setKeychains:(NSArray *)keychains
{
    NSMutableArray *skeychains = nil;
    if (keychains != nil) {
        skeychains = [NSMutableArray arrayWithCapacity:[keychains count]];
        for (LKKCKeychain *keychain in keychains)
            [skeychains addObject:(id)keychain.SecKeychain];
    }
    
    OSStatus status = SecTrustSetKeychains(_strust, skeychains);
    if (status) { // Unexpected
        LKKCReportError(status, NULL, @"Can't set keychain search list");
        return;
    }
}

- (NSDate *)verifyDate
{
    CFAbsoluteTime absoluteTime = SecTrustGetVerifyTime(_strust);
    return [NSDate dateWithTimeIntervalSinceReferenceDate:absoluteTime];
}

- (void)setVerifyDate:(NSDate *)verifyDate
{
    OSStatus status = SecTrustSetVerifyDate(_strust, (CFDateRef)verifyDate);
    if (status) { // Unexpected
        LKKCReportError(status, NULL, @"Can't set verify date");
        return;
    }
}

#pragma mark - Evaluation

- (LKKCTrustResult)evaluateWithError:(NSError **)error
{
    SecTrustResultType result = kSecTrustResultOtherError;
    OSStatus status = SecTrustEvaluate(_strust, &result);
    if (status) {
        LKKCReportError(status, error, @"Can't evaluate trust for certificate");
        return (result == kSecTrustResultInvalid ? result : LKKCTrustResultOtherError);
    }
    switch (result) {
        case kSecTrustResultProceed: // User explicitly allowed trust for this chain
            return LKKCTrustResultProceed;
        case kSecTrustResultConfirm: // User confirmation required before proceeding
            return LKKCTrustResultConfirm;
        case kSecTrustResultDeny: // User explicitly denied trust for this chain
            return LKKCTrustResultDeny;
        case kSecTrustResultUnspecified: // User did not specify a trust setting for this chain
            return LKKCTrustResultUnspecified;
        case kSecTrustResultRecoverableTrustFailure: // Can succeed after changing parameters (e.g. verify date)
            return LKKCTrustResultRecoverableTrustFailure;
        case kSecTrustResultFatalTrustFailure: // Trust denied, no simple fix
            return LKKCTrustResultFatalTrustFailure;
        case kSecTrustResultInvalid: // Invalid input
            LKKCReportError(errSecInvalidValue, error, @"Trust evaluation failed");
            return LKKCTrustResultInvalid;
        case kSecTrustResultOtherError: // Internal error
            LKKCReportError(errSecInternalError, error, @"Trust evaluation failed");
            return LKKCTrustResultOtherError;
        default:
            LKKCReportError(errSecInternalError, error, @"Invalid trust result %d", result);
            return LKKCTrustResultOtherError;
    }
}

- (NSArray *)certificateChain 
{
    CFIndex count = SecTrustGetCertificateCount(_strust);
    if (count == 0)
        return nil;
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:count];
    for (CFIndex i = 0; i < count; i++) {
        SecCertificateRef scertificate = SecTrustGetCertificateAtIndex(_strust, i);
        LKKCCertificate *certificate = [LKKCCertificate certificateWithSecCertificate:scertificate];
        [result addObject:certificate];
    }
    return result;
}

- (LKKCKey *)publicKey
{
    SecKeyRef skey = SecTrustCopyPublicKey(_strust);
    if (skey == NULL)
        return nil;
    return [LKKCKey keyWithSecKey:skey];
}

- (SecTrustRef)SecTrust
{
    return _strust;
}
@end
