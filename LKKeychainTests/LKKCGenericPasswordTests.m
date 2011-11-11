//
//  LKKCGenericPasswordTests.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-11.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCGenericPasswordTests.h"

#import <Cocoa/Cocoa.h>
//#import "application_headers" as required

@implementation LKKCGenericPasswordTests

// All code under test is in the Application
- (void)testApp
{
    id yourApplicationDelegate = [NSApplication sharedApplication];
    STAssertNotNil(yourApplicationDelegate, @"NSApplication failed to find the shared application");
}

@end
