//
//  LKKCKeychainItem+Subclasses.h
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-11-01.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKeychainItem.h"

@interface LKKCKeychainItem (Subclasses)

+ (id)itemWithClass:(CFTypeRef)itemClass persistentID:(NSData *)persistentID error:(NSError **)error;
+ (id)itemWithClass:(CFTypeRef)itemClass SecKeychainItem:(SecKeychainItemRef)sitem;
+ (id)itemWithClass:(CFTypeRef)itemClass SecKeychainItem:(SecKeychainItemRef)sitem attributes:(NSDictionary *)attributes;

+ (CFTypeRef)itemClass;
+ (void)registerSubclass:(Class)cls;

- (id)initWithSecKeychainItem:(SecKeychainItemRef)sitem attributes:(NSDictionary *)attributes;

- (void)setAttribute:(CFTypeRef)attribute toValue:(CFTypeRef)value;
- (id)valueForAttribute:(CFTypeRef)attribute;
- (SecAccessRef)access;
@end