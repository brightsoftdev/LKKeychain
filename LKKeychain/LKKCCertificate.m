//
//  LKKCCertificate.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCCertificate.h"
#import "LKKCKeychainItem+Subclasses.h"
#import "LKKCKey.h"
#import "LKKCUtil.h"

@implementation LKKCCertificate

+ (CFTypeRef)itemClass
{
    return kSecClassCertificate;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"<%@ %p '%@'>", [self className], self, self.label];
}

#pragma mark - Attributes

- (NSString *)label
{
    return [[self attributes] objectForKey:kSecAttrLabel];
}

- (void)setLabel:(NSString *)label
{
    [self setAttribute:kSecAttrLabel toValue:label];
}

- (NSData *)subject
{
    NSData *subject = [[self attributes] objectForKey:kSecAttrSubject];
    if (subject == nil && SecCertificateCopyNormalizedSubjectContent != NULL) { // 10.7
        NSError *error = nil;
        subject = (NSData *)SecCertificateCopyNormalizedSubjectContent(self.SecCertificate, (CFErrorRef *)&error);
        if (subject == nil) {
            LKKCReportErrorObj(error, NULL, @"Can't get normalized subject content");
        }
        [subject autorelease];
    }
    return subject;
}

- (NSData *)issuer
{
    NSData *issuer = [[self attributes] objectForKey:kSecAttrIssuer];
    if (issuer == nil && SecCertificateCopyNormalizedIssuerContent != NULL) { // 10.7
        NSError *error = nil;
        issuer = (NSData *)SecCertificateCopyNormalizedIssuerContent(self.SecCertificate, (CFErrorRef *)&error);
        if (issuer == nil) {
            LKKCReportErrorObj(error, NULL, @"Can't get normalized issuer content");
        }
        [issuer autorelease];
    }
    return issuer;
}

- (NSData *)serialNumber
{
    return [[self attributes] objectForKey:kSecAttrSerialNumber];
}

- (NSData *)subjectKeyID
{
    return [[self attributes] objectForKey:kSecAttrSubjectKeyID];
}

- (NSData *)publicKeyHash
{
    return [[self attributes] objectForKey:kSecAttrPublicKeyHash];
}

- (id)certificateType
{
    return [[self attributes] objectForKey:kSecAttrCertificateType];
}

- (id)certificateEncoding
{
    return [[self attributes] objectForKey:kSecAttrCertificateEncoding];
}

- (SecCertificateRef)SecCertificate
{
    return (SecCertificateRef)self.SecKeychainItem;
}

#pragma mark - Extra information

- (NSString *)commonName
{
    CFStringRef cn = NULL;
    OSStatus status = SecCertificateCopyCommonName(self.SecCertificate, &cn);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get common name from certificate");
        return nil;
    }
    return [(NSString *)cn autorelease];
}

- (NSString *)subjectSummary
{
    CFStringRef summary = SecCertificateCopySubjectSummary(self.SecCertificate);
    return [(NSString *)summary autorelease];
}

- (NSArray *)emailAddresses
{
    CFArrayRef addresses = NULL;
    OSStatus status = SecCertificateCopyEmailAddresses(self.SecCertificate, &addresses);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get email addresses from certificate");
        return nil;
    }
    return [(NSArray *)addresses autorelease];
}

- (LKKCKey *)publicKey
{
    SecKeyRef key = NULL;
    OSStatus status = SecCertificateCopyPublicKey(self.SecCertificate, &key);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get public key from certificate");
        return nil;
    }
    LKKCAssert(key != NULL);
    LKKCKey *result = [LKKCKey itemWithClass:kSecClassKey SecKeychainItem:(SecKeychainItemRef)key error:NULL];
    CFRelease(key);
    return result;
}

@end
