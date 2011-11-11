//
//  LKKCKeychainTests.m
//  LKKCKeychainTests
//
//  Created by Karoly Lorentey on 2011-10-22.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeychainTests.h"
#import "LKKeychain.h"

@implementation LKKCKeychainTests {
    BOOL _userInteractionEnabled;
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
    [super setUp];

    NSError *error = nil;
    _userInteractionEnabled = [LKKCKeychain userInteractionEnabled];
    BOOL result = [LKKCKeychain setUserInteractionEnabled:NO error:&error];
    should(result);
}

- (void)tearDown
{
    NSError *error = nil;
    BOOL result = [LKKCKeychain setUserInteractionEnabled:_userInteractionEnabled error:&error];
    should(result);

    [super tearDown];
}

- (void)testUserInteraction
{
    BOOL enabled = [LKKCKeychain userInteractionEnabled];
    NSLog(@"User interaction enabled: %d", enabled);
    NSError *error = nil;
    BOOL result;
    result = [LKKCKeychain setUserInteractionEnabled:!enabled error:&error];
    should(result);
    should([LKKCKeychain userInteractionEnabled] == !enabled);
    result = [LKKCKeychain setUserInteractionEnabled:enabled error:&error];
    should(result);
    should([LKKCKeychain userInteractionEnabled] == enabled);
}

- (void)testNonexistentKeychain
{
    NSError *error = nil;
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"Test-nonexistent.keychain"];
    LKKCKeychain *keychain = [LKKCKeychain keychainWithPath:path error:&error];
    should(keychain == nil && error != nil);
}

- (void)testKeychainCreationAndDeletion
{
    NSError *error = nil;
    BOOL result;
    
    NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"Test-New.keychain"];
    LKKCKeychain *keychain = [LKKCKeychain keychainWithPath:path error:&error];
    if (keychain != nil) {
        result = [keychain deleteKeychainWithError:&error];
        should(result);
    }
    
    keychain = [LKKCKeychain createKeychainWithPath:path password:@"foobar" error:&error];
    should(keychain != nil);
    
    should([[NSFileManager defaultManager] fileExistsAtPath:path]);
    
    should(!keychain.locked);
    should(keychain.readable);
    should(keychain.writable);
    
    should([keychain.genericPasswords count] == 0);
    should([keychain.internetPasswords count] == 0);

    @autoreleasepool {
        LKKCGenericPassword *password = [LKKCGenericPassword createPassword:@"foobar" service:@"service" account:@"account"];
        result = [password addToKeychain:keychain error:&error];
        should(result);
    }
    
    should([keychain.genericPasswords count] == 1);
    should([keychain.internetPasswords count] == 0);

    @autoreleasepool {
        LKKCGenericPassword *password2 = [keychain genericPasswordWithService:@"service" account:@"account"];
        should(password2 != nil);
        should([password2.password isEqualToString:@"foobar"]);
    }
    
    result = [keychain deleteKeychainWithError:&error];
    should(result);
    should(![[NSFileManager defaultManager] fileExistsAtPath:path]);
}

- (void)testLock
{
    LKKCKeychain *keychain = [self createTestKeychain];
    should(!keychain.locked);
    NSError *error = nil;
    BOOL result = [keychain lockWithError:&error];
    should(result);
    should(keychain.locked);
    result = [keychain unlockWithPassword:@"wrongpassword" error:&error];
    should(!result && error != nil);
    should(keychain.locked);
    result = [keychain unlockWithPassword:@"foobar" error:&error];
    should(result);
    should(!keychain.locked);
    
    result = [keychain deleteKeychainWithError:&error];
    should(result);
}

- (void)logKeychainParameters:(LKKCKeychain *)keychain
{
    NSLog(@"================");
    NSLog(@"Keychain: %@", keychain);
    NSLog(@"- locked: %d", keychain.locked);
    NSLog(@"- readable: %d", keychain.readable);
    NSLog(@"- writable: %d", keychain.writable);
    NSLog(@"- lock interval: %g", keychain.lockInterval);
    NSLog(@"- locks on sleep: %d", keychain.lockOnSleep);
    NSLog(@"- contents:");
    NSLog(@"   - %lu generic passwords", [[keychain genericPasswords] count]);
    NSLog(@"   - %lu internet passwords", [[keychain internetPasswords] count]);
    NSLog(@"   - %lu certificates", [[keychain certificates] count]);
    NSLog(@"   - %lu public keys", [[keychain publicKeys] count]);
    NSLog(@"   - %lu private keys", [[keychain privateKeys] count]);
    NSLog(@"   - %lu identitites", [[keychain identities] count]);
    NSLog(@"   - %lu symmetric keys", [[keychain symmetricKeys] count]);    
}

- (void)testDefaultKeychain
{
    NSError *error = nil;
    LKKCKeychain *keychain = [LKKCKeychain defaultKeychainWithError:&error];
    should(keychain != nil);
    [self logKeychainParameters:keychain];
}

- (void)testSearchList
{
    NSError *error = nil;
    NSArray *searchList = [LKKCKeychain keychainsInSearchListWithError:&error];
    should(searchList != nil);
    should([searchList count] > 0);
    
    NSLog(@"Keychain search list:");
    for (LKKCKeychain *keychain in searchList) {
        [self logKeychainParameters:keychain];
    }
}

@end
