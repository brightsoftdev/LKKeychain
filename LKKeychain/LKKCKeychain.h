//
//  LKKCKeychain.h
//  LKKCKeychain
//
//  Created by Karoly Lorentey on 2011-10-22.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

@class LKKCGenericPassword;
@class LKKCInternetPassword;
@class LKKCCertificate;
@class LKKCIdentity;
@class LKKCKey;

@interface LKKCKeychain : NSObject
{
@private
    SecKeychainRef _skeychain;
}

+ (LKKCKeychain *)defaultKeychain;
+ (LKKCKeychain *)keychainWithPath:(NSString *)path error:(NSError **)error;
+ (LKKCKeychain *)keychainWithSecKeychain:(SecKeychainRef)skeychain;
+ (LKKCKeychain *)createKeychainWithPath:(NSString *)path password:(NSString *)password error:(NSError **)error; // Prompts the user when password is nil.
+ (NSArray *)keychainsInSearchListWithError:(NSError **)error; // Array of LKKCKeychain objects.

// Controls whether the system is allowed to prompt the user (to unlock a keychain, to confirm an operation, etc.).
// When user interaction is disabled, operations that require it return an error.
+ (BOOL)userInteractionEnabled;
+ (BOOL)setUserInteractionEnabled:(BOOL)enabled error:(NSError **)error;

// Generic passwords.
- (NSArray *)genericPasswords;
- (LKKCGenericPassword *)genericPasswordWithPersistentID:(NSData *)persistentID;
- (LKKCGenericPassword *)genericPasswordWithService:(NSString *)service account:(NSString *)account;

// Internet passwords.
- (NSArray *)internetPasswords;
- (LKKCInternetPassword *)internetPasswordWithPersistentID:(NSData *)persistentID;
- (NSArray *)internetPasswordsForServer:(NSString *)server;

// Certificates.
- (NSArray *)certificates;
- (LKKCCertificate *)certificateWithPersistentID:(NSData *)persistentID;
- (NSArray *)certificatesWithSubject:(NSData *)subject;
- (NSArray *)certificatesWithPublicKeyHash:(NSData *)publicKeyHash;
- (NSArray *)certificatesWithLabel:(NSString *)label;

// Identities.
- (NSArray *)identities;

// Keys.
- (NSArray *)publicKeys;
- (NSArray *)privateKeys;
- (NSArray *)symmetricKeys;
- (LKKCKey *)keyWithPersistentID:(NSData *)persistentID;
- (NSArray *)publicKeysWithLabel:(NSString *)label;
- (NSArray *)privateKeysWithLabel:(NSString *)label;
- (NSArray *)symmetricKeysWithLabel:(NSString *)label;

// Path to this keychain.
@property (readonly) NSString *path;

// Current Keychain status.
@property (readonly, getter = isLocked) BOOL locked;
@property (readonly, getter = isReadable) BOOL readable;
@property (readonly, getter = isWritable) BOOL writable;

// Keychain properties.  
// The keychain must be unlocked to access these.
@property (nonatomic, readonly) BOOL lockOnSleep;
@property (nonatomic, readonly) NSTimeInterval lockInterval; // 0 when there is no lock interval.
- (BOOL)setLockOnSleep:(BOOL)lockOnSleep error:(NSError **)error;
- (BOOL)setLockInterval:(NSTimeInterval)lockInterval error:(NSError **)error;

// Keychain operations.
- (BOOL)lockWithError:(NSError **)error;
- (BOOL)unlockWithPassword:(NSString *)password error:(NSError **)error; // Prompts the user when password is nil.
- (BOOL)deleteKeychainWithError:(NSError **)error;

// Access to the underlying keychain reference.
- (SecKeychainRef)SecKeychain;
@end
