//
//  LKKCKeychainItem.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-23.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

@class LKKCKeychain;

@interface LKKCKeychainItem : NSObject
+ (id)itemWithClass:(CFTypeRef)itemClass persistentID:(NSData *)persistentID;
+ (id)itemWithClass:(CFTypeRef)itemClass SecKeychainItem:(SecKeychainItemRef)sitem;
+ (id)itemWithClass:(CFTypeRef)itemClass SecKeychainItem:(SecKeychainItemRef)sitem attributes:(NSDictionary *)attributes;

@property (nonatomic, readonly) NSData *persistentID;
@property (nonatomic, copy) NSData *rawData;

@property (nonatomic, readonly) LKKCKeychain *keychain;
@property (nonatomic, readonly) SecKeychainItemRef SecKeychainItem;

- (BOOL)saveItem;
- (void)revertItem;
- (BOOL)deleteItem;

@end

@interface LKKCKeychainItem (Subclasses)
+ (CFTypeRef)itemClass;

- (id)initWithSecKeychainItem:(SecKeychainItemRef)sitem attributes:(NSDictionary *)attributes;

@property (nonatomic, readonly) NSDictionary *attributes;

- (BOOL)setAttribute:(CFTypeRef)attribute toValue:(CFTypeRef)value;
@end