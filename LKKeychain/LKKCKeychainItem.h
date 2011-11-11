//
//  LKKCKeychainItem.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-23.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

@class LKKCKeychain;

@interface LKKCKeychainItem : NSObject
@property (nonatomic, readonly) NSData *persistentID;
@property (nonatomic, copy) NSData *rawData;

@property (nonatomic, readonly) LKKCKeychain *keychain;
@property (nonatomic, readonly) SecKeychainItemRef SecKeychainItem;

// Save modifications to the keychain.
- (BOOL)saveItemWithError:(NSError **)error;

// Reloads item from keychain.
- (void)revertItem;

// Add item to keychain. Object is refreshed to reflect the change.
- (BOOL)addToKeychain:(LKKCKeychain *)keychain error:(NSError **)error;

// Delete item from its keychain.
- (BOOL)deleteItemWithError:(NSError **)error;
- (BOOL)isDeleted;

@end
