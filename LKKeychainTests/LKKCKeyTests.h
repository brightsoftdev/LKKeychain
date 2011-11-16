//
//  LKKCKeyTests.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-13.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#define STEnableDeprecatedAssertionMacros
#import <SenTestingKit/SenTestingKit.h>
#import "LKKeychainTestUtils.h"

@interface LKKCKeyTests : SenTestCase
{
@private
    LKKCKeychain *_keychain;
}

@end
