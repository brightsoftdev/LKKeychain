//
//  LKKCGenericPasswordTests.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-11.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#define STEnableDeprecatedAssertionMacros
#import <SenTestingKit/SenTestingKit.h>
#import "LKKeychainTestUtils.h"

@interface LKKCGenericPasswordTests : SenTestCase
{
@private
    LKKCKeychain *_keychain;
}

@end
