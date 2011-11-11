//
//  LKKCGenericPasswordTests.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-11.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCGenericPasswordTests.h"

#import <Cocoa/Cocoa.h>
#import "LKKeychain.h"

@implementation LKKCGenericPasswordTests
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

- (void)testBasic
{
    BOOL result;
    NSError *error = nil;
    
    NSData *persistentID = nil;
    @autoreleasepool {
        LKKCGenericPassword *password = [LKKCGenericPassword createPassword:@"origpassword" service:@"origservice" account:@"origaccount"];
        
        should(password != nil);
        
        // Test setters.
        shouldBeEqual(password.service, @"origservice");
        password.service = @"service";
        shouldBeEqual(password.service, @"service");
        
        shouldBeEqual(password.account, @"origaccount");
        password.account = @"account";
        shouldBeEqual(password.account, @"account");
        
        shouldBeEqual(password.password, @"origpassword");
        password.password = @"password";
        shouldBeEqual(password.password, @"password");
        
        shouldBeEqual(password.label, nil);
        password.label = @"label";
        shouldBeEqual(password.label, @"label");
        
        shouldBeEqual(password.kind, nil);
        password.kind = @"kind";
        shouldBeEqual(password.kind, @"kind");
        
        shouldBeEqual(password.comment, nil);
        password.comment = @"comment";
        shouldBeEqual(password.comment, @"comment");
        
        // Add to keychain.
        shouldBeEqual(password.keychain, nil);
        should(password.SecKeychainItem == NULL);
        result = [password addToKeychain:_keychain error:&error];
        should(result);
        should(password.SecKeychainItem != NULL);
        shouldBeEqual(password.keychain, _keychain);
        
        shouldBeEqual(password.service, @"service");
        shouldBeEqual(password.account, @"account");
        shouldBeEqual(password.password, @"password");
        shouldBeEqual(password.label, @"label");
        shouldBeEqual(password.kind, @"kind");
        shouldBeEqual(password.comment, @"comment");
        should(password.creationDate != nil);
        should(password.modificationDate != nil);
        
        persistentID = [password.persistentID retain];
    }
    [persistentID autorelease];
    
    // Try to re-read from keychain.
    @autoreleasepool {
        NSArray *passwords = _keychain.genericPasswords;
        should(passwords != nil);
        should([passwords count] == 1);
        
        LKKCGenericPassword *password = [passwords objectAtIndex:0];
        should(password != nil);

        should(password.SecKeychainItem != NULL);
        shouldBeEqual(password.keychain, _keychain);
        
        shouldBeEqual(password.persistentID, persistentID);

        shouldBeEqual(password.service, @"service");
        shouldBeEqual(password.account, @"account");
        shouldBeEqual(password.password, @"password");
        shouldBeEqual(password.label, @"label");
        shouldBeEqual(password.kind, @"kind");
        shouldBeEqual(password.comment, @"comment");
        should(password.creationDate != nil);
        should(password.modificationDate != nil);
        
        // Try setters on an existing item
        password.service = @"newservice";
        password.account = @"newaccount";
        password.password = @"newpassword";
        password.label = @"newlabel";
        password.kind = @"newkind";
        password.comment = @"newcomment";
        
        shouldBeEqual(password.service, @"newservice");
        shouldBeEqual(password.account, @"newaccount");
        shouldBeEqual(password.password, @"newpassword");
        shouldBeEqual(password.label, @"newlabel");
        shouldBeEqual(password.kind, @"newkind");
        shouldBeEqual(password.comment, @"newcomment");
        
        // Try saving the item.
        result = [password saveItemWithError:&error];
        should(result);
        
        shouldBeEqual(password.service, @"newservice");
        shouldBeEqual(password.account, @"newaccount");
        shouldBeEqual(password.password, @"newpassword");
        shouldBeEqual(password.label, @"newlabel");
        shouldBeEqual(password.kind, @"newkind");
        shouldBeEqual(password.comment, @"newcomment");
        
        // Persistent ID changes when we change a primary key.
        should(![persistentID isEqualTo:password.persistentID]);
        persistentID = [password.persistentID retain];
    }
    [persistentID autorelease];
    
    // Try service/account-based lookup.
    @autoreleasepool {
        LKKCGenericPassword *password = [_keychain genericPasswordWithService:@"newservice" account:@"newaccount"];
        should(password != nil);
        
        shouldBeEqual(password.persistentID, persistentID);
        
        shouldBeEqual(password.service, @"newservice");
        shouldBeEqual(password.account, @"newaccount");
        shouldBeEqual(password.password, @"newpassword");
        shouldBeEqual(password.label, @"newlabel");
        shouldBeEqual(password.kind, @"newkind");
        shouldBeEqual(password.comment, @"newcomment");
        should(password.creationDate != nil);
        should(password.modificationDate != nil);
        
        // Try reverting.
        password.service = @"unsavedservice";
        shouldBeEqual(password.service, @"unsavedservice");
        [password revertItem];
        shouldBeEqual(password.service, @"newservice");
    }
    
    // Try lookup from persistent ID.
    @autoreleasepool {
        LKKCGenericPassword *password = [_keychain genericPasswordWithPersistentID:persistentID];
        should(password != nil);
        
        shouldBeEqual(password.persistentID, persistentID);
        
        shouldBeEqual(password.service, @"newservice");
        shouldBeEqual(password.account, @"newaccount");
        shouldBeEqual(password.password, @"newpassword");
        shouldBeEqual(password.label, @"newlabel");
        shouldBeEqual(password.kind, @"newkind");
        shouldBeEqual(password.comment, @"newcomment");
        should(password.creationDate != nil);
        should(password.modificationDate != nil);
        
        result = [password deleteItemWithError:&error];
        should(result);
    }
}

- (NSString *)randomStringOfLength:(NSInteger)length withPrefix:(int)prefix
{
    const static char *lookupTable = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890)!@#$%^&*()-=[];'\\,./`_+{}:\"|<>?";
    size_t tablesize = strlen(lookupTable);
    
    NSMutableString *result = [NSMutableString string];
    if (prefix != 0) 
        [result appendFormat:@"%d ", prefix];
    for (int i = 0; i < length; i++) {
        size_t rnd = arc4random() % tablesize;
        char c = lookupTable[rnd];
        [result appendFormat:@"%c", c];
    }
    return result;
}

- (void)testBulkCreation
{
    BOOL result;
    NSError *error = nil;
    int count = 20;
    
    // Create a bunch of random passwords.
    NSMutableArray *pwds = [NSMutableArray array];
    for (int i = 0; i < count; i++) {
        @autoreleasepool {
            NSString *passwordString = [self randomStringOfLength:20 withPrefix:0];
            NSString *service = [self randomStringOfLength:20 withPrefix:0];
            NSString *account = [self randomStringOfLength:30 withPrefix:i];
            NSString *label = [self randomStringOfLength:40 withPrefix:i];
            NSString *comment = [self randomStringOfLength:100 withPrefix:0];
            LKKCGenericPassword *item = [LKKCGenericPassword createPassword:passwordString service:service account:account];
            item.label = label;
            item.comment = comment;
            result = [item addToKeychain:_keychain error:&error];
            should(result);
            if (result) {
                [pwds addObject:[NSDictionary dictionaryWithObjectsAndKeys:
                                 passwordString, @"password",
                                 service, @"service",
                                 account, @"account",
                                 label, @"label",
                                 comment, @"comment",
                                 item.persistentID, @"persistentID",
                                 nil]];
            }
        }
    }
    
    // Try to read them back by service/account.
    for (int i = 0; i < count; i++) {
        @autoreleasepool {
            NSDictionary *desc = [pwds objectAtIndex:i];
            NSString *service = [desc objectForKey:@"service"];
            NSString *account = [desc objectForKey:@"account"];
            LKKCGenericPassword *item = [_keychain genericPasswordWithService:service account:account];
            should(item != nil);
            for (NSString *key in [desc allKeys]) {
                shouldBeEqual([item valueForKey:key], [desc objectForKey:key]);
            }
        }
    }
    
    // Try to read them back by persistent ID.
    for (int i = 0; i < count; i++) {
        @autoreleasepool {
            NSDictionary *desc = [pwds objectAtIndex:i];
            LKKCGenericPassword *item = [_keychain genericPasswordWithPersistentID:[desc objectForKey:@"persistentID"]];
            should(item != nil);
            for (NSString *key in [desc allKeys]) {
                shouldBeEqual([item valueForKey:key], [desc objectForKey:key]);
            }
        }
    }
    
    // Delete them.
    @autoreleasepool {
        NSArray *keychainPwds = _keychain.genericPasswords;
        should([keychainPwds count] == count);
        for (LKKCGenericPassword *item in keychainPwds) {
            result = [item deleteItemWithError:&error];
            should(result);
        }
    }
    
    
}
@end
