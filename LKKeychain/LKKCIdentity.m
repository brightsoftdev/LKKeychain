//
//  LKKCIdentity.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright © 2011, Károly Lőrentey. All rights reserved.
//  
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are met:
//  
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//  * Neither the name of Károly Lőrentey nor the names of its contributors 
//    may be used to endorse or promote products derived from this software 
//    without specific prior written permission.
//  
//  **This software is provided by the copyright holders and contributors "as is" and
//  any express or implied warranties, including, but not limited to, the implied
//  warranties of merchantability and fitness for a particular purpose are
//  disclaimed. In no event shall Károly Lőrentey be liable for any
//  direct, indirect, incidental, special, exemplary, or consequential damages
//  (including, but not limited to, procurement of substitute goods or services;
//  loss of use, data, or profits; or business interruption) however caused and
//  on any theory of liability, whether in contract, strict liability, or tort
//  (including negligence or otherwise) arising in any way out of the use of this
//  software, even if advised of the possibility of such damage.**
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
