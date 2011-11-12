//
//  LKKCKey.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-24.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import "LKKCKey.h"
#import "LKKCKeychainItem+Subclasses.h"

@implementation LKKCKey

+ (void)load
{
    if (self != [LKKCKey class])
        return;
    [LKKCKeychainItem registerSubclass:self];
}

+ (CFTypeRef)itemClass
{
    return kSecClassKey;
}

- (NSString *)label
{
    return [self valueForAttribute:kSecAttrLabel];
}

- (SecKeyRef)SecKey
{
    return (SecKeyRef)self.SecKeychainItem;
}

@end
