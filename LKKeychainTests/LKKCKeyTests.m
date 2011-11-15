//
//  LKKCKeyTests.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-13.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeyTests.h"
#import "LKKeychainTestUtils.h"

@implementation LKKCKeyTests
{
    LKKCKeychain *_keychain;
}

- (void)setUp
{
    _keychain = [[LKKeychainTestUtils createTestKeychain:@"Test"] retain];
}

- (void)tearDown
{
    [_keychain release];
    _keychain = nil;
}

@end
