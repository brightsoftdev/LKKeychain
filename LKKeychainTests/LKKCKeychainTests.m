//
//  LKKCKeychainTests.m
//  LKKCKeychainTests
//
//  Created by Karoly Lorentey on 2011-10-22.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeychainTests.h"
#import "LKKCKeychain.h"

@implementation LKKCKeychainTests {
    BOOL _userInteractionEnabled;
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
    
    NSLog(@"Generic passwords:");
    NSLog(@"%@", [keychain genericPasswords]);

    NSLog(@"Internet passwords:");
    NSLog(@"%@", [keychain internetPasswords]);

    NSLog(@"Certificates:");
    NSLog(@"%@", [keychain certificates]);
    
    NSLog(@"Identities:");
    NSLog(@"%@", [keychain identities]);
    
    NSLog(@"Public keys:");
    NSLog(@"%@", [keychain publicKeys]);
    
    NSLog(@"Private keys:");
    NSLog(@"%@", [keychain privateKeys]);
    
    NSLog(@"Symmetric keys:");
    NSLog(@"%@", [keychain symmetricKeys]);
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
