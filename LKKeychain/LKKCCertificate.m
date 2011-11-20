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
        return [subject autorelease];
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
