//
//  AESTests.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-15.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#define STEnableDeprecatedAssertionMacros
#import <SenTestingKit/SenTestingKit.h>
#import "LKKeychainTestUtils.h"

@interface AESTests : SenTestCase
{
@private
    LKKCKeychain *_keychain;
}

@end
