//
//  LKKCIdentity.m
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
