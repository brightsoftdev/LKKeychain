//
//  LKKCGenericPassword.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-23.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeychainItem.h"

@interface LKKCGenericPassword : LKKCKeychainItem

//kSecClassGenericPassword item attributes:
//kSecAttrAccess
//kSecAttrCreator
//kSecAttrType

@property (nonatomic, retain) NSString *label; // kSecAttrLabel
@property (nonatomic, retain) NSString *itemDescription; // kSecAttrDescription
@property (nonatomic, retain) NSString *comment; // kSecAttrComment

@property (nonatomic, readonly) NSDate *creationDate; // kSecAttrCreationDate
@property (nonatomic, readonly) NSDate *modificationDate; // kSecAttrModificationDate

@property (nonatomic, assign, getter = isInvisible) BOOL invisible; // kSecAttrIsInvisible
@property (nonatomic, assign, getter = isNegative) BOOL negative; // kSecAttrIsNegative

@property (nonatomic, retain) NSString *service; // kSecAttrService
@property (nonatomic, retain) NSString *account; // kSecAttrAccount
@property (nonatomic, retain) NSData *appSpecificData; // kSecAttrGeneric

@property (nonatomic, retain) NSString *password;
@end
