//
//  LKKCKeyTests.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-13.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeyTests.h"
#import "LKKeychain.h"

@implementation LKKCKeyTests
{
    LKKCKeychain *_keychain;
}

- (LKKCKeychain *)createTestKeychain
{
    NSError *error = nil;
    BOOL result;
    
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"Test.keychain"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
        LKKCKeychain *oldkeychain = [LKKCKeychain keychainWithPath:path error:&error];
        if (oldkeychain != nil) {
            result = [oldkeychain deleteKeychainWithError:&error];
            should(result);
        }
    }
    LKKCKeychain *keychain = [[LKKCKeychain createKeychainWithPath:path password:@"foobar" error:&error] retain];
    should(keychain != nil);
    
    should(!keychain.locked);
    should(keychain.readable);
    should(keychain.writable);
    return keychain;
}

- (void)setUp
{
    _keychain = [[self createTestKeychain] retain];
}

- (void)tearDown
{
    [_keychain release];
    _keychain = nil;
}

- (void)testSymmetricGeneration
{
    NSError *error = nil;
    BOOL result;
    
    // Generate a key into a keychain.
    @autoreleasepool {
        LKKCKeyGenerator *generator = [LKKCKeyGenerator generator];
        should(generator != nil);
        generator.keychain = _keychain;
        LKKCKey *key = [generator generateAESKey];
        should(key != nil);
        
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyTypeAES);
        should(key.keySize == 128);
    }

    // Generate a floating key.
    @autoreleasepool {
        LKKCKeyGenerator *generator = [LKKCKeyGenerator generator];
        should(generator != nil);
        LKKCKey *key = [generator generateAESKey];
        should(key != nil);
        
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyTypeAES);
        should(key.keySize == 128);
        
        result = [key addToKeychain:_keychain error:&error];
        should(result);
    }
}


@end
