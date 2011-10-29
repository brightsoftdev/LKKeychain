//
//  LKKCKeychain.h
//  LKKCKeychain
//
//  Created by Karoly Lorentey on 2011-10-22.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface LKKCKeychain : NSObject
+ (LKKCKeychain *)defaultKeychain;
+ (LKKCKeychain *)keychainWithPath:(NSString *)path;
+ (LKKCKeychain *)keychainWithSecKeychain:(SecKeychainRef)skeychain;
+ (LKKCKeychain *)createKeychainWithPath:(NSString *)path password:(NSString *)password; // Prompts the user when password is nil.
+ (NSArray *)keychainsInSearchList; // Array of LKKCKeychain objects.
- (id)initWithSecKeychain:(SecKeychainRef)skeychain;

// Controls whether the system is allowed to prompt the user on certain operations.
+ (BOOL)userInteractionEnabled;
+ (void)setUserInteractionEnabled:(BOOL)enabled;

// Listing keychain contents.
- (NSArray *)internetPasswords;
- (NSArray *)genericPasswords;
- (NSArray *)certificates;
- (NSArray *)publicKeys;
- (NSArray *)privateKeys;
- (NSArray *)identities;
- (NSArray *)symmetricKeys;

// Keychain properties.
@property (readonly) NSString *path;
@property (readonly) SecKeychainStatus status;
@property (readonly, getter = isLocked) BOOL locked;
@property (readonly, getter = isReadable) BOOL readable;
@property (readonly, getter = isWritable) BOOL writable;

@property (nonatomic, assign) BOOL lockOnSleep;
@property (nonatomic, assign) NSTimeInterval lockInterval; // 0 when there is no lock interval.

// Keychain operations.
- (BOOL)lock;
- (BOOL)unlockWithPassword:(NSString *)password; // Prompts the user when password is nil.
- (BOOL)deleteKeychain;

// Access to the underlying keychain reference.
- (SecKeychainRef)SecKeychain;
@end
