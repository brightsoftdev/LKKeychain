//
//  LKKeychainTestCase.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-15.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import <Foundation/Foundation.h>

#define STEnableDeprecatedAssertionMacros
#import <SenTestingKit/SenTestingKit.h>

#import <LKKeychain/LKKeychain.h>

@interface LKKeychainTestCase : SenTestCase
{
@protected
    LKKCKeychain *_keychain;
}

- (LKKCKeychain *)createTestKeychain:(NSString *)name;

- (LKKCCertificate *)certificateFromResourceName:(NSString *)name;
- (LKKCCertificate *)validCA;
- (LKKCCertificate *)expiredCA;
- (LKKCCertificate *)intermediateCA;
- (LKKCCertificate *)validCert;
- (LKKCCertificate *)expiredCert;
- (LKKCCertificate *)corruptCert;
- (LKKCCertificate *)validCertWithExpiredCA;
- (LKKCCertificate *)validCertWithIntermediateCA;
- (LKKCCertificate *)expiredCertWithIntermediateCA;

- (NSDate *)notYetValidDate;
- (NSDate *)validDateForExpiredCerts;

@end
