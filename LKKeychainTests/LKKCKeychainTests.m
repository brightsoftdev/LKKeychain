//
//  LKKCKeychainTests.m
//  LKKCKeychainTests
//
//  Created by Karoly Lorentey on 2011-10-22.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeychainTests.h"

@implementation LKKCKeychainTests 

- (void)setUp
{
    [super setUp];
    _userInteractionEnabled = [LKKCKeychain userInteractionAllowed];
    [LKKCKeychain setUserInteractionAllowed:NO];
}

- (void)tearDown
{
    [LKKCKeychain setUserInteractionAllowed:_userInteractionEnabled];
    [super tearDown];
}

- (void)testUserInteraction
{
    BOOL allowed = [LKKCKeychain userInteractionAllowed];
    NSLog(@"User interaction allowed: %d", allowed);
    [LKKCKeychain setUserInteractionAllowed:!allowed];
    should([LKKCKeychain userInteractionAllowed] == !allowed);
    [LKKCKeychain setUserInteractionAllowed:allowed];
    should([LKKCKeychain userInteractionAllowed] == allowed);
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
    LKKCKeychain *keychain = [LKKeychainTestUtils createTestKeychain:@"LockTest"];
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
    NSLog(@"   - %u generic passwords", (unsigned int)[[keychain genericPasswords] count]);
    NSLog(@"   - %u internet passwords", (unsigned int)[[keychain internetPasswords] count]);
    NSLog(@"   - %u certificates", (unsigned int)[[keychain certificates] count]);
    NSLog(@"   - %u public keys", (unsigned int)[[keychain publicKeys] count]);
    NSLog(@"   - %u private keys", (unsigned int)[[keychain privateKeys] count]);
    NSLog(@"   - %u identitites", (unsigned int)[[keychain identities] count]);
    NSLog(@"   - %u symmetric keys", (unsigned int)[[keychain symmetricKeys] count]);    
}

- (void)testDefaultKeychain
{
    LKKCKeychain *keychain = [LKKCKeychain defaultKeychain];
    should(keychain != nil);
    [self logKeychainParameters:keychain];
}

- (void)testSearchList
{
    NSArray *searchList = [LKKCKeychain keychainsOnSearchList];
    should(searchList != nil);
    should([searchList count] > 0);
    
    NSLog(@"Keychain search list:");
    for (LKKCKeychain *keychain in searchList) {
        [self logKeychainParameters:keychain];
    }
}

@end
