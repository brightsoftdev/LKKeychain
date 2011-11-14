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
    BOOL result;
    
    // Generate a key into a keychain.
    NSData *persistentID = nil;
    @autoreleasepool {
        NSError *error = nil;
        LKKCKeyGenerator *generator = [LKKCKeyGenerator generator];
        should(generator != nil);
        generator.keychain = _keychain;
        generator.applicationLabel = @"test key ID";
        generator.label = @"test key label";
        generator.tag = @"test key tag";
        LKKCKey *key = [generator generateAESKey];
        should(key != nil);
        
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyTypeAES);
        should(key.keySize == 128);
        shouldBeEqual(key.label, @"test key label");
        shouldBeEqual(key.applicationLabel, @"test key ID");
        shouldBeEqual(key.tag, @"test key tag");

        persistentID = [key.persistentID retain];
        should(persistentID != nil);
        
        result = [key addToKeychain:_keychain error:&error];
        should(!result);
        should([error code] == errSecDuplicateItem);
    }
    
    @autoreleasepool {
        NSArray *keys = [_keychain symmetricKeys];
        should([keys count] == 1);
        LKKCKey *key = [keys objectAtIndex:0];
        
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyTypeAES);
        should(key.keySize == 128);
        shouldBeEqual(key.label, @"test key label");
        shouldBeEqual(key.applicationLabel, @"test key ID");
        shouldBeEqual(key.tag, @"test key tag");
    }
    
    @autoreleasepool {
        LKKCKey *key = [_keychain keyWithPersistentID:persistentID];
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyTypeAES);
        should(key.keySize == 128);
        shouldBeEqual(key.label, @"test key label");
        shouldBeEqual(key.applicationLabel, @"test key ID");
        shouldBeEqual(key.tag, @"test key tag");
    }
    [persistentID release];
    persistentID = nil;

    // Generate a floating key.
    @autoreleasepool {
        NSError *error = nil;
        LKKCKeyGenerator *generator = [LKKCKeyGenerator generator];
        should(generator != nil);
        generator.applicationLabel = @"floating key ID";
        generator.label = @"floating key label";
        generator.tag = @"floating key tag";
        LKKCKey *key = [generator generateAESKey];
        should(key != nil);
        
        should(key.keyClass == LKKCKeyClassSymmetric);
        should(key.keyType == LKKCKeyTypeAES);
        should(key.keySize == 128);
        
        result = [key addToKeychain:_keychain error:&error];
        should(result);
        result = [key addToKeychain:_keychain error:&error];
        should(!result);
        should([error code] == errSecDuplicateItem);
    }
}


@end
