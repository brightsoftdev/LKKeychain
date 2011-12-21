//
//  LKKCTrustTests.h
//  LKKeychain
//
//  Created by Károly Lőrentey on 2011-12-21.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#define STEnableDeprecatedAssertionMacros
#import <SenTestingKit/SenTestingKit.h>
#import "LKKeychainTestUtils.h"

@interface LKKCTrustTests : SenTestCase
{
@private
    LKKCKeychain *_keychain;
}

@end
