//
//  LKKCGenericPassword.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-23.
//  Copyright (c) 2011 Karoly Lorentey. All rights reserved.
//

#import <Security/Security.h>

#import "LKKCGenericPassword.h"
#import "LKKCUtil.h"

@implementation LKKCGenericPassword

+ (CFTypeRef)itemClass
{
    return kSecClassGenericPassword;
}

- (NSString *)description
{
    if (self.SecKeychainItem == NULL)
        return [NSString stringWithFormat:@"<%@ %p (deleted)>", [self className], self];
    return [NSString stringWithFormat:@"<%@ %p service='%@' account='%@'>", 
            [self className], self, self.service, self.account];
}

- (NSString *)label
{
    return [self.attributes objectForKey:kSecAttrLabel];
}

- (void)setLabel:(NSString *)label
{
    [self setAttribute:kSecAttrLabel toValue:label];
}

- (NSString *)itemDescription
{
    return [self.attributes objectForKey:kSecAttrDescription];
}

- (void)setItemDescription:(NSString *)description
{
    [self setAttribute:kSecAttrDescription toValue:description];
}

- (NSString *)comment
{
    return [self.attributes objectForKey:kSecAttrComment];
}

- (void)setComment:(NSString *)comment
{
    [self setAttribute:kSecAttrComment toValue:comment];
}

- (NSDate *)creationDate
{
    return [self.attributes objectForKey:kSecAttrCreationDate];
}

- (NSDate *)modificationDate
{
    return [self.attributes objectForKey:kSecAttrModificationDate];
}


- (NSString *)account 
{
    return [self.attributes objectForKey:kSecAttrAccount];
}

- (void)setAccount:(NSString *)account
{
    [self setAttribute:kSecAttrAccount toValue:account];
}

- (NSString *)service 
{
    return [self.attributes objectForKey:kSecAttrService];
}

- (void)setService:(NSString *)service 
{
    [self setAttribute:kSecAttrService toValue:service];
}

- (NSData *)appSpecificData
{
    return [self.attributes objectForKey:kSecAttrGeneric];
}

- (void)setAppSpecificData:(NSData *)appSpecificData
{
    [self setAttribute:kSecAttrGeneric toValue:appSpecificData];
}

- (BOOL)isInvisible
{
    CFBooleanRef value = (CFBooleanRef)[self.attributes objectForKey:kSecAttrIsInvisible];
    return (value ? CFBooleanGetValue(value) : NO);
}

- (void)setInvisible:(BOOL)invisible
{
    [self setAttribute:kSecAttrIsInvisible toValue:(invisible ? kCFBooleanTrue : kCFBooleanFalse)];
}

- (BOOL)isNegative
{
    CFBooleanRef value = (CFBooleanRef)[self.attributes objectForKey:kSecAttrIsNegative];
    return (value ? CFBooleanGetValue(value) : NO);
}

- (void)setNegative:(BOOL)negative
{
    [self setAttribute:kSecAttrIsNegative toValue:(negative ? kCFBooleanTrue : kCFBooleanFalse)];
}

- (NSString *)password
{
    NSData *data = self.rawData;
    NSString *password = [[NSString alloc] initWithBytes:[data bytes] length:[data length] encoding:NSUTF8StringEncoding];
    return [password autorelease];
}

- (void)setPassword:(NSString *)password 
{
    NSData *data = [password dataUsingEncoding:NSUTF8StringEncoding];
    [self setAttribute:kSecValueData toValue:data];
}

@end