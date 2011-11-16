//
//  LKKeychainTests.h
//  LKKeychainTests
//
//  Created by Karoly Lorentey on 2011-10-22.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#define STEnableDeprecatedAssertionMacros
#import <SenTestingKit/SenTestingKit.h>
#import "LKKeychainTestUtils.h"

@interface LKKCKeychainTests : SenTestCase
{
@private
    BOOL _userInteractionEnabled;
}
@end
