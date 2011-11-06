//
//  LKKCGenericPassword.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-23.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeychainItem.h"

@interface LKKCGenericPassword : LKKCKeychainItem

// Service name. Shows up as "Where" in Keychain Access. (kSecAttrService)
// For application-specific passwords, use the app's bundle ID for this field.
@property (nonatomic, retain) NSString *service;

// Account name. Shows up as "Account" in Keychain Access. (kSecAttrAccount)
@property (nonatomic, retain) NSString *account;

// The password value.
@property (nonatomic, retain) NSString *password;

// The human-readable name of this password. Shows up as "Name" in Keychain Access. (kSecAttrLabel)
@property (nonatomic, retain) NSString *label;

// The human-readable item kind ("Application Password" by default). Shows up as "Kind" in Keychain Access. (kSecAttrDescription)
@property (nonatomic, retain) NSString *itemDescription;

// Human-readable comment. Shows up as "Comments" in Keychain Access. (kSecAttrComment)
@property (nonatomic, retain) NSString *comment;

// Creation date. (kSecAttrCreationDate)
@property (nonatomic, readonly) NSDate *creationDate;

// Modification date. (KSecAttrModificationDate)
@property (nonatomic, readonly) NSDate *modificationDate;

// If YES, password value doesn't show in Keychain Access. (kSecAttrIsInvisible)
@property (nonatomic, assign, getter = isInvisible) BOOL invisible;

// If YES, item has no password; user has disabled password storage for this account. (kSecAttrIsNegative)
@property (nonatomic, assign, getter = isNegative) BOOL negative;

// Application-specific metadata. Does not show in Keychain Access. (kSecAttrGeneric)
@property (nonatomic, retain) NSData *appSpecificData;

@end

//kSecClassGenericPassword item attributes not represented above:
//kSecAttrAccess
//kSecAttrCreator
//kSecAttrType

