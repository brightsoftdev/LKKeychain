//
//  LKKCKeyTests.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-13.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeyTests.h"

@implementation LKKCKeyTests

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
