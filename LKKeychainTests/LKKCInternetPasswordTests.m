//
//  LKKCInternetPasswordTests.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-12.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCInternetPasswordTests.h"
#import "LKKeychainTestUtils.h"

@implementation LKKCInternetPasswordTests
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

- (void)testBasic
{
    BOOL result;
    NSError *error = nil;
    
    NSData *persistentID = nil;
    @autoreleasepool {
        LKKCInternetPassword *password = [LKKCInternetPassword createPassword];

        // Test setters.
        shouldBeEqual(password.label, nil);
        password.label = @"label";
        shouldBeEqual(password.label, @"label");
        
        shouldBeEqual(password.kind, nil);
        password.kind = @"kind";
        shouldBeEqual(password.kind, @"kind");
        
        shouldBeEqual(password.comment, nil);
        password.comment = @"comment";
        shouldBeEqual(password.comment, @"comment");
        
        shouldBeEqual(password.account, nil);
        password.account = @"account";
        shouldBeEqual(password.account, @"account");
        
        shouldBeEqual(password.securityDomain, nil);
        password.securityDomain = @"securityDomain";
        shouldBeEqual(password.securityDomain, @"securityDomain");
        
        shouldBeEqual(password.server, nil);
        password.server = @"example.com";
        shouldBeEqual(password.server, @"example.com");
        
        should(password.protocol == LKKCProtocolAny);
        password.protocol = LKKCProtocolHTTP;
        should(password.protocol == LKKCProtocolHTTP);
        
        should(password.authenticationType == LKKCAuthenticationTypeAny);
        password.authenticationType = LKKCAuthenticationTypeHTTPBasic;
        should(password.authenticationType == LKKCAuthenticationTypeHTTPBasic);
        
        shouldBeEqual(password.path, nil);
        password.path = @"/path/to/somewhere";
        shouldBeEqual(password.path, @"/path/to/somewhere");
        
        shouldBeEqual(password.password, nil);
        password.password = @"password";
        shouldBeEqual(password.password, @"password");
        
        // Add to keychain.
        shouldBeEqual(password.keychain, nil);
        should(password.SecKeychainItem == NULL);
        result = [password addToKeychain:_keychain error:&error];
        should(result);
        should(password.SecKeychainItem != NULL);
        shouldBeEqual(password.keychain, _keychain);

        shouldBeEqual(password.label, @"label");
        shouldBeEqual(password.kind, @"kind");
        shouldBeEqual(password.comment, @"comment");
        shouldBeEqual(password.account, @"account");
        shouldBeEqual(password.securityDomain, @"securityDomain");
        shouldBeEqual(password.server, @"example.com");
        should(password.protocol == LKKCProtocolHTTP);
        should(password.authenticationType == LKKCAuthenticationTypeHTTPBasic);
        shouldBeEqual(password.path, @"/path/to/somewhere");
        shouldBeEqual(password.password, @"password");
        should(password.creationDate != nil);
        should(password.modificationDate != nil);
        
        persistentID = [password.persistentID retain];
    }
    [persistentID autorelease];
    
    // Try to re-read from keychain.
    @autoreleasepool {
        NSArray *passwords = _keychain.internetPasswords;
        should(passwords != nil);
        should([passwords count] == 1);
        
        LKKCInternetPassword *password = [passwords objectAtIndex:0];
        should(password != nil);
        
        should(password.SecKeychainItem != NULL);
        shouldBeEqual(password.keychain, _keychain);
        
        shouldBeEqual(password.persistentID, persistentID);
        
        shouldBeEqual(password.label, @"label");
        shouldBeEqual(password.kind, @"kind");
        shouldBeEqual(password.comment, @"comment");
        shouldBeEqual(password.account, @"account");
        shouldBeEqual(password.securityDomain, @"securityDomain");
        shouldBeEqual(password.server, @"example.com");
        should(password.protocol == LKKCProtocolHTTP);
        should(password.authenticationType == LKKCAuthenticationTypeHTTPBasic);
        shouldBeEqual(password.path, @"/path/to/somewhere");
        shouldBeEqual(password.password, @"password");
        should(password.creationDate != nil);
        should(password.modificationDate != nil);
        
        // Try setters on an existing item
        password.label = @"newlabel";
        password.kind = @"newkind";
        password.comment = @"newcomment";
        password.account = @"newaccount";
        password.securityDomain = @"newsecurityDomain";
        password.server = @"new.example.com";
        password.protocol = LKKCProtocolHTTPS;
        password.authenticationType = LKKCAuthenticationTypeHTTPDigest;
        password.path = @"/another/path";
        password.password = @"newpassword";
        
        shouldBeEqual(password.label, @"newlabel");
        shouldBeEqual(password.kind, @"newkind");
        shouldBeEqual(password.comment, @"newcomment");
        shouldBeEqual(password.account, @"newaccount");
        shouldBeEqual(password.securityDomain, @"newsecurityDomain");
        shouldBeEqual(password.server, @"new.example.com");
        should(password.protocol == LKKCProtocolHTTPS);
        should(password.authenticationType == LKKCAuthenticationTypeHTTPDigest);
        shouldBeEqual(password.path, @"/another/path");
        shouldBeEqual(password.password, @"newpassword");
        should(password.creationDate != nil);
        should(password.modificationDate != nil);
        
        // Try saving the item.
        result = [password saveItemWithError:&error];
        should(result);
        
        shouldBeEqual(password.label, @"newlabel");
        shouldBeEqual(password.kind, @"newkind");
        shouldBeEqual(password.comment, @"newcomment");
        shouldBeEqual(password.account, @"newaccount");
        shouldBeEqual(password.securityDomain, @"newsecurityDomain");
        shouldBeEqual(password.server, @"new.example.com");
        should(password.protocol == LKKCProtocolHTTPS);
        should(password.authenticationType == LKKCAuthenticationTypeHTTPDigest);
        shouldBeEqual(password.path, @"/another/path");
        shouldBeEqual(password.password, @"newpassword");
        should(password.creationDate != nil);
        should(password.modificationDate != nil);
        
        // Persistent ID changes when we change a primary key.
        should(![persistentID isEqualTo:password.persistentID]);
        persistentID = [password.persistentID retain];
    }
    [persistentID autorelease];
    
    // Try content-based lookup.
    @autoreleasepool {
        NSArray *passwords = [_keychain internetPasswordsForServer:@"new.example.com"];
        should(passwords != nil);
        should([passwords count] == 1);
        
        LKKCInternetPassword *password = [passwords objectAtIndex:0];
        
        shouldBeEqual(password.label, @"newlabel");
        shouldBeEqual(password.kind, @"newkind");
        shouldBeEqual(password.comment, @"newcomment");
        shouldBeEqual(password.account, @"newaccount");
        shouldBeEqual(password.securityDomain, @"newsecurityDomain");
        shouldBeEqual(password.server, @"new.example.com");
        should(password.protocol == LKKCProtocolHTTPS);
        should(password.authenticationType == LKKCAuthenticationTypeHTTPDigest);
        shouldBeEqual(password.path, @"/another/path");
        shouldBeEqual(password.password, @"newpassword");
        should(password.creationDate != nil);
        should(password.modificationDate != nil);

        shouldBeEqual(password.persistentID, persistentID);
                
        // Try reverting.
        password.password = @"unsavedpassword";
        shouldBeEqual(password.password, @"unsavedpassword");
        [password revertItem];
        shouldBeEqual(password.password, @"newpassword");
    }
    
    // Try lookup from persistent ID.
    @autoreleasepool {
        LKKCInternetPassword *password = [_keychain internetPasswordWithPersistentID:persistentID];
        should(password != nil);
        
        shouldBeEqual(password.label, @"newlabel");
        shouldBeEqual(password.kind, @"newkind");
        shouldBeEqual(password.comment, @"newcomment");
        shouldBeEqual(password.account, @"newaccount");
        shouldBeEqual(password.securityDomain, @"newsecurityDomain");
        shouldBeEqual(password.server, @"new.example.com");
        should(password.protocol == LKKCProtocolHTTPS);
        should(password.authenticationType == LKKCAuthenticationTypeHTTPDigest);
        shouldBeEqual(password.path, @"/another/path");
        shouldBeEqual(password.password, @"newpassword");
        should(password.creationDate != nil);
        should(password.modificationDate != nil);
        
        shouldBeEqual(password.persistentID, persistentID);
        
        result = [password deleteItemWithError:&error];
        should(result);
    }
    
    @autoreleasepool {
        LKKCInternetPassword *password = [_keychain internetPasswordWithPersistentID:persistentID];
        should(password == nil);
    }
}

- (void)testURL
{
    @autoreleasepool {
        LKKCInternetPassword *password = [LKKCInternetPassword createPassword];
        
        // Set attributes via an URL
        NSURL *url = [NSURL URLWithString:@"http://account@example.com:1234/foo/bar"];
        password.url = url;
        
        shouldBeEqual(password.account, @"account");
        shouldBeEqual(password.securityDomain, nil);
        shouldBeEqual(password.server, @"example.com");
        should(password.protocol == LKKCProtocolHTTP);
        should(password.authenticationType == LKKCAuthenticationTypeAny);
        should(password.port == 1234);
        shouldBeEqual(password.path, @"/foo/bar");
        
        shouldBeEqual(password.url, url);
    }
    
    @autoreleasepool {
        LKKCInternetPassword *password = [LKKCInternetPassword createPassword];
        
        password.protocol = LKKCProtocolHTTPS;
        password.account = @"account";
        password.server = @"example.com";
        password.port = 1234;
        password.path = @"/foo/bar";
        
        shouldBeEqual(password.url, [NSURL URLWithString:@"https://account@example.com:1234/foo/bar"]);
    }
}

- (void)testDeletedItem
{
    NSError *error = nil;
    BOOL result;
    LKKCGenericPassword *password = [LKKCGenericPassword createPassword:@"secret" 
                                                                service:@"service" 
                                                                account:@"account"];
    result = [password addToKeychain:_keychain error:&error];
    should(result);
    
    LKKCGenericPassword *password2 = [_keychain genericPasswordWithService:@"service" account:@"account"];
    result = [password2 deleteItemWithError:&error];
    should(result);
    
    LKKCGenericPassword *password3 = [_keychain genericPasswordWithService:@"service" account:@"account"];
    should(password3 == nil);
    
    LKKCGenericPassword *password4 = [LKKCGenericPassword createPassword:@"secret2" 
                                                                 service:@"service"
                                                                 account:@"account"];
    result = [password4 addToKeychain:_keychain error:&error];
    should(result);
    result = [password4 addToKeychain:_keychain error:&error];
    should(!result);
    should([error code] == errSecDuplicateItem);
    
}
@end
