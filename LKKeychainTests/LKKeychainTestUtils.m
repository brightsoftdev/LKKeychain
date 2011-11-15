//
//  LKKeychainTestUtils.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-15.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKeychainTestUtils.h"
#import "LKKeychain.h"

@implementation LKKeychainTestUtils

+ (LKKCKeychain *)createTestKeychain:(NSString *)name
{
    NSError *error = nil;
    BOOL result;

    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:[name stringByAppendingPathExtension:@".keychain"]];
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
        LKKCKeychain *oldkeychain = [LKKCKeychain keychainWithPath:path error:&error];
        if (oldkeychain != nil) {
            result = [oldkeychain deleteKeychainWithError:&error];
            if (!result)
                return nil;
        }
    }
    LKKCKeychain *keychain = [[LKKCKeychain createKeychainWithPath:path password:@"foobar" error:&error] retain];
    return keychain;
}


@end
