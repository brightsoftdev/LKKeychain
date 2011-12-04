//
//  LKKCGenericPassword.m
//  LKKeychain
//
//  Created by Karoly Lorentey on 2011-10-23.
//  Copyright © 2011, Károly Lőrentey. All rights reserved.
//  
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are met:
//  
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//  * Neither the name of Károly Lőrentey nor the names of its contributors 
//    may be used to endorse or promote products derived from this software 
//    without specific prior written permission.
//  
//  **This software is provided by the copyright holders and contributors "as is" and
//  any express or implied warranties, including, but not limited to, the implied
//  warranties of merchantability and fitness for a particular purpose are
//  disclaimed. In no event shall Károly Lőrentey be liable for any
//  direct, indirect, incidental, special, exemplary, or consequential damages
//  (including, but not limited to, procurement of substitute goods or services;
//  loss of use, data, or profits; or business interruption) however caused and
//  on any theory of liability, whether in contract, strict liability, or tort
//  (including negligence or otherwise) arising in any way out of the use of this
//  software, even if advised of the possibility of such damage.**
// 

#import <Security/Security.h>

#import "LKKCGenericPassword.h"
#import "LKKCKeychainItem+Subclasses.h"
#import "LKKCUtil.h"

@implementation LKKCGenericPassword

+ (void)load
{
    if (self != [LKKCGenericPassword class])
        return;
    [LKKCKeychainItem registerSubclass:self];
}

+ (CFTypeRef)itemClass
{
    return kSecClassGenericPassword;
}

+ (LKKCGenericPassword *)createPassword:(NSString *)password 
                                service:(NSString *)service
                                account:(NSString *)account
{
    LKKCGenericPassword *item = [[LKKCGenericPassword alloc] initWithSecKeychainItem:nil attributes:nil];
    item.service = service;
    item.account = account;
    item.password = password;
    item.label = service;
    return [item autorelease];
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
    return [self valueForAttribute:kSecAttrLabel];
}

- (void)setLabel:(NSString *)label
{
    [self setAttribute:kSecAttrLabel toValue:label];
}

- (NSString *)kind
{
    return [self valueForAttribute:kSecAttrDescription];
}

- (void)setKind:(NSString *)kind
{
    [self setAttribute:kSecAttrDescription toValue:kind];
}

- (NSString *)comment
{
    return [self valueForAttribute:kSecAttrComment];
}

- (void)setComment:(NSString *)comment
{
    [self setAttribute:kSecAttrComment toValue:comment];
}

- (NSDate *)creationDate
{
    return [self valueForAttribute:kSecAttrCreationDate];
}

- (NSDate *)modificationDate
{
    return [self valueForAttribute:kSecAttrModificationDate];
}


- (NSString *)account 
{
    return [self valueForAttribute:kSecAttrAccount];
}

- (void)setAccount:(NSString *)account
{
    [self setAttribute:kSecAttrAccount toValue:account];
}

- (NSString *)service 
{
    return [self valueForAttribute:kSecAttrService];
}

- (void)setService:(NSString *)service 
{
    [self setAttribute:kSecAttrService toValue:service];
}

- (NSData *)appSpecificData
{
    return [self valueForAttribute:kSecAttrGeneric];
}

- (void)setAppSpecificData:(NSData *)appSpecificData
{
    [self setAttribute:kSecAttrGeneric toValue:appSpecificData];
}

- (BOOL)isInvisible
{
    CFBooleanRef value = (CFBooleanRef)[self valueForAttribute:kSecAttrIsInvisible];
    return (value ? CFBooleanGetValue(value) : NO);
}

- (void)setInvisible:(BOOL)invisible
{
    [self setAttribute:kSecAttrIsInvisible toValue:(invisible ? kCFBooleanTrue : kCFBooleanFalse)];
}

- (BOOL)isNegative
{
    CFBooleanRef value = (CFBooleanRef)[self valueForAttribute:kSecAttrIsNegative];
    return (value ? CFBooleanGetValue(value) : NO);
}

- (void)setNegative:(BOOL)negative
{
    [self setAttribute:kSecAttrIsNegative toValue:(negative ? kCFBooleanTrue : kCFBooleanFalse)];
}

- (NSString *)password
{
    return [self passwordWithError:NULL];
}

- (NSString *)passwordWithError:(NSError **)error
{
    NSData *data = [self rawDataWithError:error];
    if (data == nil)
        return nil;
    NSString *password = [[NSString alloc] initWithBytes:[data bytes] length:[data length] encoding:NSUTF8StringEncoding];
    return [password autorelease];
}

- (void)setPassword:(NSString *)password 
{
    NSData *data = [password dataUsingEncoding:NSUTF8StringEncoding];
    [self setAttribute:kSecValueData toValue:data];
}

@end
