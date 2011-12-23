//
//  LKKCCertificate.m
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

#import "LKKCCertificate.h"
#import "LKKCKeychainItem+Subclasses.h"
#import "LKKCKey.h"
#import "LKKCUtil.h"

@implementation LKKCCertificate

+ (void)load
{
    if (self != [LKKCCertificate class])
        return;
    [LKKCKeychainItem registerSubclass:self];
}

+ (CFTypeRef)itemClass
{
    return kSecClassCertificate;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"<%@ %p '%@'>", [self className], self, self.label];
}

+ (LKKCCertificate *)certificateWithDERData:(NSData *)data
{
    SecCertificateRef scertificate = SecCertificateCreateWithData(kCFAllocatorDefault, (CFDataRef)data);
    LKKCCertificate *certificate = [[LKKCCertificate alloc] initWithSecKeychainItem:(SecKeychainItemRef)scertificate attributes:nil];
    CFRelease(scertificate);
    return [certificate autorelease];
}

+ (LKKCCertificate *)certificateWithSecCertificate:(SecCertificateRef)scertificate
{
    LKKCCertificate *certificate = [[LKKCCertificate alloc] initWithSecKeychainItem:(SecKeychainItemRef)scertificate attributes:nil];
    return [certificate autorelease];
}


#pragma mark - Attributes

- (NSString *)label
{
    return [self valueForAttribute:kSecAttrLabel];
}

- (void)setLabel:(NSString *)label
{
    [self setAttribute:kSecAttrLabel toValue:label];
}

- (NSData *)subject
{
    SecCertificateRef scertificate = self.SecCertificate;
    if (scertificate == NULL)
        return nil;
    NSData *subject = [self valueForAttribute:kSecAttrSubject];
    if (subject != nil)
        return subject;
    if (SecCertificateCopyNormalizedSubjectContent != NULL) { // 10.7
        CFErrorRef error = NULL;
        subject = (NSData *)SecCertificateCopyNormalizedSubjectContent(scertificate, &error);
        if (subject == nil) {
            LKKCReportErrorObj((NSError *)error, NULL, @"Can't get normalized subject content");
            CFRelease(error);
        }
        [subject autorelease];

        NSUInteger length = [subject length];
        const char *bytes = (const char *)[subject bytes];
        if (length > 0 && bytes[0] != 0x30) {
            // SecCertificateCopyNormalizedSubjectContent does not include the topmost SEQUENCE tag.
            // This seems to be a bug in 10.7, since kSecAttrSubject does include it, as does
            // SecCertificateCopyNormalizedIssuerContent.
            // Work around this issue by gluing the tag back using duct tape.
            if (length > 65535) {
                // I don't feel like writing a full DER encoder.
                LKKCReportError(errSecInternalError, NULL, @"Normalized subject DN is too long");
                return nil;
            }
            size_t tagLength = (length < 128 ? 2 : 4);
            NSMutableData *newSubject = [NSMutableData dataWithCapacity:tagLength + length];
            if (length < 128) {
                UInt8 b[2] = { '\x30', (UInt8)length };
                [newSubject appendBytes:&b length:2];
            }
            else {
                UInt8 b[4] = { '\x30', 2, (UInt8)(length >> 8), (UInt8)length };
                [newSubject appendBytes:&b length:4];
            }
            [newSubject appendData:subject];
            subject = newSubject;
        }
        return subject;
    }
    return nil;
}

- (NSData *)issuer
{
    SecCertificateRef scertificate = self.SecCertificate;
    if (scertificate == NULL)
        return nil;
    NSData *issuer = [self valueForAttribute:kSecAttrIssuer];
    if (issuer != nil)
        return issuer;
    if (SecCertificateCopyNormalizedIssuerContent != NULL) { // 10.7
        CFErrorRef error = NULL;
        issuer = (NSData *)SecCertificateCopyNormalizedIssuerContent(scertificate, &error);
        if (issuer == nil) {
            LKKCReportErrorObj((NSError *)error, NULL, @"Can't get normalized issuer content");
            CFRelease(error);
        }
        return [issuer autorelease];
    }
    return nil;
}

- (NSData *)serialNumber
{
    SecCertificateRef scertificate = self.SecCertificate;
    if (scertificate == NULL)
        return nil;
    return [self valueForAttribute:kSecAttrSerialNumber];
}

- (NSData *)subjectKeyID
{
    SecCertificateRef scertificate = self.SecCertificate;
    if (scertificate == NULL)
        return nil;
    return [self valueForAttribute:kSecAttrSubjectKeyID];
}

- (NSData *)publicKeyHash
{
    SecCertificateRef scertificate = self.SecCertificate;
    if (scertificate == NULL)
        return nil;
    return [self valueForAttribute:kSecAttrPublicKeyHash];
}

- (id)certificateType
{
    SecCertificateRef scertificate = self.SecCertificate;
    if (scertificate == NULL)
        return nil;
    return [self valueForAttribute:kSecAttrCertificateType];
}

- (id)certificateEncoding
{
    SecCertificateRef scertificate = self.SecCertificate;
    if (scertificate == NULL)
        return nil;
    return [self valueForAttribute:kSecAttrCertificateEncoding];
}

- (SecCertificateRef)SecCertificate
{
    return (SecCertificateRef)_sitem;
}

#pragma mark - Extra information

- (NSString *)commonName
{
    SecCertificateRef scertificate = self.SecCertificate;
    if (scertificate == NULL)
        return nil;
    CFStringRef cn = NULL;
    OSStatus status = SecCertificateCopyCommonName(scertificate, &cn);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get common name from certificate");
        return nil;
    }
    return [(NSString *)cn autorelease];
}

- (NSString *)subjectSummary
{
    SecCertificateRef scertificate = self.SecCertificate;
    if (scertificate == NULL)
        return nil;
    CFStringRef summary = SecCertificateCopySubjectSummary(scertificate);
    return [(NSString *)summary autorelease];
}

- (NSArray *)emailAddresses
{
    SecCertificateRef scertificate = self.SecCertificate;
    if (scertificate == NULL)
        return nil;
    CFArrayRef addresses = NULL;
    OSStatus status = SecCertificateCopyEmailAddresses(scertificate, &addresses);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get email addresses from certificate");
        return nil;
    }
    return [(NSArray *)addresses autorelease];
}

- (LKKCKey *)publicKey
{
    SecCertificateRef scertificate = self.SecCertificate;
    if (scertificate == NULL)
        return nil;
    SecKeyRef key = NULL;
    OSStatus status = SecCertificateCopyPublicKey(scertificate, &key);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get public key from certificate");
        return nil;
    }
    LKKCAssert(key != NULL);
    LKKCKey *result = [LKKCKey itemWithClass:kSecClassKey SecKeychainItem:(SecKeychainItemRef)key];
    CFRelease(key);
    return result;
}

- (NSData *)data
{
    SecCertificateRef scertificate = self.SecCertificate;
    if (scertificate == NULL)
        return nil;
    NSData *data = (NSData *)SecCertificateCopyData(scertificate);
    return [data autorelease];
}

@end
