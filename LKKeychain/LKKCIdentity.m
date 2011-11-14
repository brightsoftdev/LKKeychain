//
//  LKKCIdentity.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCIdentity.h"
#import "LKKCKeychainItem+Subclasses.h"
#import "LKKCCertificate.h"
#import "LKKCKey.h"
#import "LKKCUtil.h"

@implementation LKKCIdentity

+ (void)load
{
    if (self != [LKKCIdentity class])
        return;
    [LKKCKeychainItem registerSubclass:self];
}

+ (CFTypeRef)itemClass
{
    return kSecClassIdentity;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"<%@ %p '%@'>", [self className], self, self.label];
}

- (LKKCCertificate *)certificate 
{
    SecCertificateRef scertificate = NULL;
    OSStatus status = SecIdentityCopyCertificate(self.SecIdentity, &scertificate);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get certificate from identity");
        return nil;
    }
    LKKCCertificate *certificate = [LKKCCertificate itemWithClass:kSecClassCertificate SecKeychainItem:(SecKeychainItemRef)scertificate];
    CFRelease(scertificate);
    return certificate;
}

- (LKKCKey *)privateKey
{
    SecKeyRef skey = NULL;
    OSStatus status = SecIdentityCopyPrivateKey(self.SecIdentity, &skey);
    if (status) {
        LKKCReportError(status, NULL, @"Can't get private key from identity");
        return nil;
    }
    LKKCKey *key = [LKKCKey itemWithClass:kSecClassKey SecKeychainItem:(SecKeychainItemRef)skey];
    CFRelease(skey);
    return key;
}

- (NSString *)label 
{
    return [self valueForAttribute:kSecAttrLabel];
}

- (SecIdentityRef)SecIdentity
{
    return (SecIdentityRef)_sitem;
}
@end
